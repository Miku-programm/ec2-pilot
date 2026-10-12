"""Contract tests use Botocore Stubber; no AWS credentials or network required."""
import base64
from datetime import datetime, timezone
from unittest.mock import Mock

from botocore.exceptions import ReadTimeoutError
from botocore.serialize import create_serializer
from botocore.stub import ANY, Stubber
import pytest

from app.aws_service import AwsError, AwsService


IID = "i-0123456789abcdef0"
ENI = "eni-0123456789abcdef0"
AMI = "ami-0123456789abcdef0"
OLD = "eipalloc-0123456789abcdef0"
NEW = "eipalloc-1123456789abcdef0"
NEW_IP = "203.0.113.12"
PRIVATE = "10.0.1.5"
CREDENTIALS = {"access_key_id": "AKIATESTKEYEXAMPLE001", "secret_access_key": "test-secret-value-do-not-log"}


@pytest.fixture(scope="module")
def service():
    return AwsService(CREDENTIALS, "ap-southeast-2")


def instance(state="running", **overrides):
    data = {
        "InstanceId": IID, "State": {"Name": state}, "ImageId": AMI,
        "InstanceType": "t3.micro", "PrivateIpAddress": PRIVATE,
        "Placement": {"AvailabilityZone": "ap-southeast-2a"},
        "NetworkInterfaces": [{
            "NetworkInterfaceId": ENI, "PrivateIpAddress": PRIVATE,
            "Attachment": {"DeviceIndex": 0},
            "PrivateIpAddresses": [{"PrivateIpAddress": PRIVATE, "Primary": True}],
        }],
    }
    data.update(overrides)
    return data


def old_address(**overrides):
    data = {"AllocationId": OLD, "AssociationId": "eipassoc-0123456789abcdef0", "InstanceId": IID,
            "NetworkInterfaceId": ENI, "PrivateIpAddress": PRIVATE, "PublicIp": "203.0.113.11", "Domain": "vpc"}
    data.update(overrides)
    return data


def expect_instance(stub, item=None):
    stub.add_response("describe_instances", {"Reservations": [{"Instances": [item or instance()]}]}, {"InstanceIds": [IID]})


def expect_rotate_prelude(stub, previous=True):
    expect_instance(stub)
    expect_border_group(stub)
    stub.add_response("describe_addresses", {"Addresses": [old_address()] if previous else []},
                      {"Filters": [{"Name": "network-interface-id", "Values": [ENI]}]})
    stub.add_response("allocate_address", {"AllocationId": NEW, "PublicIp": NEW_IP, "Domain": "vpc"}, {"Domain": "vpc", "NetworkBorderGroup": "ap-southeast-2"})


def expect_border_group(stub, zone_name="ap-southeast-2a", border_group="ap-southeast-2", zone_type="availability-zone"):
    stub.add_response("describe_availability_zones", {"AvailabilityZones": [{"ZoneName": zone_name, "NetworkBorderGroup": border_group, "ZoneType": zone_type}]}, {"ZoneNames": [zone_name]})


ASSOCIATE_PARAMS = {"AllocationId": NEW, "NetworkInterfaceId": ENI, "PrivateIpAddress": PRIVATE, "AllowReassociation": False}


def test_validate_only_calls_sts(service):
    with Stubber(service.sts) as sts, Stubber(service.ec2) as ec2:
        sts.add_response("get_caller_identity", {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/test", "UserId": "test-user"}, {})
        assert service.validate() == {"aws_account_id": "123456789012", "arn": "arn:aws:iam::123456789012:user/test"}
        sts.assert_no_pending_responses()
        ec2.assert_no_pending_responses()


def test_explicit_region_and_no_automatic_mutation_retries(service):
    assert service.ec2.meta.region_name == "ap-southeast-2"
    assert service.sts.meta.region_name == "ap-southeast-2"
    assert service.ec2.meta.config.retries["total_max_attempts"] == 1


def test_denial_keeps_code_and_redacts_credentials(service):
    with Stubber(service.sts) as stub:
        stub.add_client_error("get_caller_identity", "AccessDenied", CREDENTIALS["secret_access_key"] + " explicit deny in a service control policy", expected_params={})
        with pytest.raises(AwsError) as error:
            service.validate()
    assert error.value.code == "AccessDenied"
    assert "service control policy" in str(error.value)
    assert CREDENTIALS["secret_access_key"] not in str(error.value)


def test_instances_are_paginated_and_do_not_require_address_permission(service):
    item = instance(Tags=[{"Key": "Name", "Value": "Sydney"}], LaunchTime=datetime(2026, 1, 1, tzinfo=timezone.utc))
    with Stubber(service.ec2) as stub:
        stub.add_response("describe_instances", {"Reservations": [{"Instances": [item]}], "NextToken": "next"}, {})
        stub.add_response("describe_instances", {"Reservations": []}, {"NextToken": "next"})
        result = service.instances()
        assert len(result) == 1
        assert result[0]["name"] == "Sydney"
        assert result[0]["launch_time"] == "2026-01-01T00:00:00+00:00"
        assert result[0]["public_ip"] is None
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("action,state,operation", [("start", "stopped", "start_instances"), ("stop", "running", "stop_instances"), ("reboot", "running", "reboot_instances")])
def test_lifecycle_scopes_request_to_selected_instance(service, action, state, operation):
    with Stubber(service.ec2) as stub:
        expect_instance(stub, instance(state))
        stub.add_response(operation, {}, {"InstanceIds": [IID]})
        assert getattr(service, action)(IID)["message"]
        stub.assert_no_pending_responses()


def test_script_update_rejects_running_instance(service):
    with Stubber(service.ec2) as stub:
        expect_instance(stub)
        with pytest.raises(AwsError, match="必须先停止"):
            service.set_user_data(IID, "#!/bin/sh\necho ready")
        stub.assert_no_pending_responses()


def test_script_update_accepts_utf8_and_passes_raw_blob(service):
    script = "#!/bin/bash\necho '你好'"
    with Stubber(service.ec2) as stub:
        expect_instance(stub, instance("stopped"))
        stub.add_response("modify_instance_attribute", {}, {"InstanceId": IID, "UserData": {"Value": script.encode("utf-8")}})
        assert "默认不会" in service.set_user_data(IID, script)["message"]
        stub.assert_no_pending_responses()


def test_modify_user_data_wire_serializer_encodes_exactly_once(service):
    script = "#!/bin/bash\necho '你好'".encode("utf-8")
    model = service.ec2.meta.service_model.operation_model("ModifyInstanceAttribute")
    serializer = create_serializer("ec2")
    request = serializer.serialize_to_request({"InstanceId": IID, "UserData": {"Value": script}}, model)
    # Verify actual Botocore query serialization, not just an implementation mock.
    assert request["body"]["UserData.Value"] == base64.b64encode(script).decode("ascii")


@pytest.mark.parametrize("action", ["launch", "set_user_data"])
def test_user_data_limit_measures_utf8_bytes_before_any_aws_call(service, action):
    script = "中" * 5462  # 16,386 bytes, although only 5,462 characters.
    with Stubber(service.ec2):
        with pytest.raises(AwsError, match="16 KiB"):
            if action == "launch":
                service.launch({"image_id": AMI, "user_data": script})
            else:
                service.set_user_data(IID, script)


def test_launch_uses_actual_ami_root_path_one_instance_and_idempotency(service):
    script = "#!/bin/bash\necho 你好"
    with Stubber(service.ec2) as stub:
        stub.add_response("describe_images", {"Images": [{"ImageId": AMI, "State": "available", "RootDeviceType": "ebs", "RootDeviceName": "/dev/sda1", "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 16}}]}]}, {"ImageIds": [AMI]})
        stub.add_response("run_instances", {"Instances": [{"InstanceId": IID}]}, {
            "ImageId": AMI, "InstanceType": "t3.micro", "MinCount": 1, "MaxCount": 1,
            "ClientToken": "stable-operation-123", "UserData": script,
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
            "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 16, "VolumeType": "gp3", "DeleteOnTermination": True, "Encrypted": True}}],
            "TagSpecifications": ANY,
        })
        result = service.launch({"image_id": AMI, "user_data": script, "volume_size": 16, "operation_token": "stable-operation-123"})
        assert result["instance_ids"] == [IID]
        stub.assert_no_pending_responses()


def test_launch_rejects_volume_smaller_than_ami_snapshot(service):
    with Stubber(service.ec2) as stub:
        stub.add_response("describe_images", {"Images": [{"ImageId": AMI, "State": "available", "RootDeviceType": "ebs", "RootDeviceName": "/dev/sda1", "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 16}}]}]}, {"ImageIds": [AMI]})
        with pytest.raises(AwsError, match="至少需要 16"):
            service.launch({"image_id": AMI, "volume_size": 8})


def test_rotate_preserves_previous_address_by_default(service, monkeypatch):
    release = Mock(wraps=service.ec2.release_address)
    monkeypatch.setattr(service.ec2, "release_address", release)
    with Stubber(service.ec2) as stub:
        expect_rotate_prelude(stub)
        stub.add_response("associate_address", {"AssociationId": "eipassoc-1123456789abcdef0"}, ASSOCIATE_PARAMS)
        result = service.rotate_ip(IID)
        assert result["public_ip"] == NEW_IP
        assert result["previous_allocation_id"] == OLD
        assert "原弹性 IP 已保留" in result["message"]
        release.assert_not_called()
        stub.assert_no_pending_responses()


def test_rotate_releases_only_verified_old_unassociated_address(service):
    with Stubber(service.ec2) as stub:
        expect_rotate_prelude(stub)
        stub.add_response("associate_address", {"AssociationId": "eipassoc-1123456789abcdef0"}, ASSOCIATE_PARAMS)
        stub.add_response("describe_addresses", {"Addresses": [{"AllocationId": OLD, "Domain": "vpc"}]}, {"AllocationIds": [OLD]})
        stub.add_response("release_address", {}, {"AllocationId": OLD, "NetworkBorderGroup": "ap-southeast-2"})
        assert "原弹性 IP 已释放" in service.rotate_ip(IID, release_previous=True)["message"]
        stub.assert_no_pending_responses()


def test_rotate_never_releases_old_ip_that_became_attached_elsewhere(service):
    with Stubber(service.ec2) as stub:
        expect_rotate_prelude(stub)
        stub.add_response("associate_address", {"AssociationId": "eipassoc-1123456789abcdef0"}, ASSOCIATE_PARAMS)
        stub.add_response("describe_addresses", {"Addresses": [old_address(InstanceId="i-1123456789abcdef0")]}, {"AllocationIds": [OLD]})
        assert "状态不明确" in service.rotate_ip(IID, release_previous=True)["message"]
        stub.assert_no_pending_responses()


def test_rotate_partial_success_returns_success_and_release_warning(service):
    with Stubber(service.ec2) as stub:
        expect_rotate_prelude(stub)
        stub.add_response("associate_address", {"AssociationId": "eipassoc-1123456789abcdef0"}, ASSOCIATE_PARAMS)
        stub.add_response("describe_addresses", {"Addresses": [{"AllocationId": OLD}]}, {"AllocationIds": [OLD]})
        stub.add_client_error("release_address", "UnauthorizedOperation", "denied", expected_params={"AllocationId": OLD, "NetworkBorderGroup": "ap-southeast-2"})
        result = service.rotate_ip(IID, release_previous=True)
        assert result["allocation_id"] == NEW
        assert "释放失败" in result["message"]


def test_definite_association_denial_cleans_only_verified_unused_new_eip(service):
    with Stubber(service.ec2) as stub:
        expect_rotate_prelude(stub)
        stub.add_client_error("associate_address", "UnauthorizedOperation", "SCP denied", expected_params=ASSOCIATE_PARAMS)
        stub.add_response("describe_addresses", {"Addresses": [{"AllocationId": NEW}]}, {"AllocationIds": [NEW]})
        stub.add_response("release_address", {}, {"AllocationId": NEW, "NetworkBorderGroup": "ap-southeast-2"})
        with pytest.raises(AwsError, match="已回收") as error:
            service.rotate_ip(IID)
        assert error.value.code == "UnauthorizedOperation"
        stub.assert_no_pending_responses()


def test_definite_denial_with_associated_new_eip_never_releases_it(service):
    with Stubber(service.ec2) as stub:
        expect_rotate_prelude(stub)
        stub.add_client_error("associate_address", "UnauthorizedOperation", "SCP denied", expected_params=ASSOCIATE_PARAMS)
        stub.add_response("describe_addresses", {"Addresses": [old_address(AllocationId=NEW)]}, {"AllocationIds": [NEW]})
        with pytest.raises(AwsError, match="已保留"):
            service.rotate_ip(IID)
        stub.assert_no_pending_responses()


def test_timeout_after_association_does_not_attempt_cleanup_or_retry(service, monkeypatch):
    describe = Mock(wraps=service.ec2.describe_addresses)
    release = Mock(wraps=service.ec2.release_address)
    monkeypatch.setattr(service.ec2, "describe_addresses", describe)
    monkeypatch.setattr(service.ec2, "release_address", release)
    with Stubber(service.ec2) as stub:
        expect_rotate_prelude(stub)
        associate = Mock(side_effect=ReadTimeoutError(endpoint_url="https://ec2.ap-southeast-2.amazonaws.com"))
        monkeypatch.setattr(service.ec2, "associate_address", associate)
        with pytest.raises(AwsError, match="已保留") as error:
            service.rotate_ip(IID)
        assert error.value.code == "AwsTransportError"
        associate.assert_called_once_with(**ASSOCIATE_PARAMS)
        assert describe.call_count == 1  # Initial old-IP lookup only; no cleanup read.
        release.assert_not_called()
        stub.assert_no_pending_responses()


def test_aws_500_association_does_not_attempt_cleanup(service, monkeypatch):
    describe = Mock(wraps=service.ec2.describe_addresses)
    release = Mock(wraps=service.ec2.release_address)
    monkeypatch.setattr(service.ec2, "describe_addresses", describe)
    monkeypatch.setattr(service.ec2, "release_address", release)
    with Stubber(service.ec2) as stub:
        expect_rotate_prelude(stub)
        stub.add_client_error("associate_address", "InternalError", "unknown result", http_status_code=500, expected_params=ASSOCIATE_PARAMS)
        with pytest.raises(AwsError, match="已保留"):
            service.rotate_ip(IID)
        assert describe.call_count == 1
        release.assert_not_called()
        stub.assert_no_pending_responses()


def test_ambiguous_primary_interface_stops_before_allocation(service):
    item = instance()
    item["NetworkInterfaces"].append(dict(item["NetworkInterfaces"][0], NetworkInterfaceId="eni-1123456789abcdef0"))
    with Stubber(service.ec2) as stub:
        expect_instance(stub, item)
        with pytest.raises(AwsError, match="唯一主网卡"):
            service.rotate_ip(IID)
        stub.assert_no_pending_responses()


def test_unknown_old_address_ownership_stops_before_allocation(service):
    with Stubber(service.ec2) as stub:
        expect_instance(stub)
        expect_border_group(stub)
        address = old_address()
        del address["InstanceId"]
        stub.add_response("describe_addresses", {"Addresses": [address]}, {"Filters": [{"Name": "network-interface-id", "Values": [ENI]}]})
        with pytest.raises(AwsError, match="归属不明确"):
            service.rotate_ip(IID)
        stub.assert_no_pending_responses()


def test_local_zone_allocates_from_its_actual_network_border_group(service):
    with Stubber(service.ec2) as stub:
        expect_instance(stub, instance(Placement={"AvailabilityZone": "ap-southeast-2-per-1a"}))
        expect_border_group(stub, "ap-southeast-2-per-1a", "ap-southeast-2-per-1", "local-zone")
        stub.add_response("describe_addresses", {"Addresses": []}, {"Filters": [{"Name": "network-interface-id", "Values": [ENI]}]})
        stub.add_response("allocate_address", {"AllocationId": NEW, "PublicIp": NEW_IP, "Domain": "vpc"}, {"Domain": "vpc", "NetworkBorderGroup": "ap-southeast-2-per-1"})
        stub.add_response("associate_address", {"AssociationId": "eipassoc-1123456789abcdef0"}, ASSOCIATE_PARAMS)
        assert service.rotate_ip(IID)["public_ip"] == NEW_IP
        stub.assert_no_pending_responses()


def test_wavelength_zone_rejected_before_allocating_an_eip(service):
    with Stubber(service.ec2) as stub:
        expect_instance(stub)
        expect_border_group(stub, zone_type="wavelength-zone")
        with pytest.raises(AwsError, match="Wavelength"):
            service.rotate_ip(IID)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("invalid", ["i-arbitrary", "i-0123456789abcdef0;ls", "", None])
def test_bad_instance_ids_rejected_before_aws_calls(service, invalid):
    with Stubber(service.ec2):
        with pytest.raises(AwsError, match="无效"):
            service.start(invalid)
