"""Contract tests use Botocore Stubber; no AWS credentials or network required."""
import base64
from datetime import datetime, timezone
from hashlib import sha256
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
    stub.add_response("allocate_address", {"AllocationId": NEW, "PublicIp": NEW_IP, "Domain": "vpc"}, ALLOCATE_TAGGED)


def expect_border_group(stub, zone_name="ap-southeast-2a", border_group="ap-southeast-2", zone_type="availability-zone"):
    stub.add_response("describe_availability_zones", {"AvailabilityZones": [{"ZoneName": zone_name, "NetworkBorderGroup": border_group, "ZoneType": zone_type}]}, {"ZoneNames": [zone_name]})


ALLOCATE_TAGGED = {
    "Domain": "vpc", "NetworkBorderGroup": "ap-southeast-2",
    "TagSpecifications": [{"ResourceType": "elastic-ip", "Tags": [
        {"Key": "ManagedBy", "Value": "ec2-panel"}, {"Key": "RotatedFor", "Value": IID},
    ]}],
}
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


def test_resources_keeps_five_latest_images_for_each_architecture_across_pages(service):
    filters = [
        {"Name": "name", "Values": ["al2023-ami-2023.*-kernel-*-x86_64", "al2023-ami-2023.*-kernel-*-arm64"]},
        {"Name": "architecture", "Values": ["x86_64", "arm64"]},
        {"Name": "state", "Values": ["available"]},
        {"Name": "root-device-type", "Values": ["ebs"]},
    ]
    images = [
        {"ImageId": f"ami-{index:017x}", "Name": f"AL2023 {architecture} {index}",
         "Architecture": architecture, "CreationDate": f"2026-{month:02d}-{index:02d}T00:00:00Z",
         "RootDeviceName": "/dev/xvda"}
        for architecture, month in (("x86_64", 10), ("arm64", 9)) for index in range(1, 8)
    ]
    with Stubber(service.ec2) as stub:
        stub.add_response("describe_images", {"Images": images[:9], "NextToken": "next"}, {"Owners": ["amazon"], "Filters": filters})
        stub.add_response("describe_images", {"Images": images[9:]}, {"Owners": ["amazon"], "Filters": filters, "NextToken": "next"})
        stub.add_response("describe_subnets", {"Subnets": []}, {})
        stub.add_response("describe_security_groups", {"SecurityGroups": []}, {})
        stub.add_response("describe_key_pairs", {"KeyPairs": []}, {})
        result = service.resources()
        assert len(result["images"]) == 10
        for architecture in ("x86_64", "arm64"):
            names = [item["name"] for item in result["images"] if item["architecture"] == architecture]
            assert names == [f"AL2023 {architecture} {index}" for index in range(7, 2, -1)]
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
        stub.add_response("describe_images", {"Images": [{"ImageId": AMI, "State": "available", "Architecture": "x86_64", "RootDeviceType": "ebs", "RootDeviceName": "/dev/sda1", "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 16}}]}]}, {"ImageIds": [AMI]})
        stub.add_response("describe_instance_types", {"InstanceTypes": [{"InstanceType": "t3.micro", "ProcessorInfo": {"SupportedArchitectures": ["x86_64"]}}]}, {"InstanceTypes": ["t3.micro"]})
        stub.add_response("run_instances", {"Instances": [{"InstanceId": IID}]}, {
            "ImageId": AMI, "InstanceType": "t3.micro", "MinCount": 1, "MaxCount": 1,
            "ClientToken": "stable-operation-123", "UserData": script,
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
            "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 16, "VolumeType": "gp3", "DeleteOnTermination": True, "Encrypted": True}}],
            "TagSpecifications": ANY,
        })
        result = service.launch({"image_id": AMI, "user_data": script, "volume_size": 16, "operation_token": "stable-operation-123", "open_all_ports": False})
        assert result["instance_ids"] == [IID]
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("instance_type", ["t4g.nano", "t4g.micro", "t4g.small"])
def test_launch_arm_instance_with_matching_ami(service, instance_type):
    with Stubber(service.ec2) as stub:
        stub.add_response("describe_images", {"Images": [{"ImageId": AMI, "State": "available", "Architecture": "arm64", "RootDeviceType": "ebs", "RootDeviceName": "/dev/xvda"}]}, {"ImageIds": [AMI]})
        stub.add_response("describe_instance_types", {"InstanceTypes": [{"InstanceType": instance_type, "ProcessorInfo": {"SupportedArchitectures": ["arm64"]}}]}, {"InstanceTypes": [instance_type]})
        stub.add_response("run_instances", {"Instances": [{"InstanceId": IID}]}, {
            "ImageId": AMI, "InstanceType": instance_type, "MinCount": 1, "MaxCount": 1,
            "ClientToken": "stable-arm-operation-123", "UserData": "",
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
            "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 8, "VolumeType": "gp3", "DeleteOnTermination": True, "Encrypted": True}}],
            "TagSpecifications": ANY,
        })
        result = service.launch({"image_id": AMI, "instance_type": instance_type, "operation_token": "stable-arm-operation-123", "open_all_ports": False})
        assert result["instance_ids"] == [IID]
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("instance_type,supported,architecture", [
    ("t4g.nano", "arm64", "x86_64"),
    ("t4g.small", "arm64", "x86_64"),
    ("t3.micro", "x86_64", "arm64"),
])
def test_launch_rejects_incompatible_ami_before_creating_resources(service, instance_type, supported, architecture):
    with Stubber(service.ec2) as stub:
        stub.add_response("describe_images", {"Images": [{"ImageId": AMI, "State": "available", "Architecture": architecture, "RootDeviceType": "ebs", "RootDeviceName": "/dev/xvda"}]}, {"ImageIds": [AMI]})
        stub.add_response("describe_instance_types", {"InstanceTypes": [{"InstanceType": instance_type, "ProcessorInfo": {"SupportedArchitectures": [supported]}}]}, {"InstanceTypes": [instance_type]})
        with pytest.raises(AwsError, match="请选择兼容的镜像") as error:
            service.launch({"image_id": AMI, "instance_type": instance_type})
        assert error.value.code == "ImageArchitectureMismatch"
        assert instance_type in error.value.message
        assert architecture in error.value.message
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("type_response,architecture,code", [
    ([], "arm64", "InvalidInstanceType"),
    ([{"InstanceType": "t3.micro", "ProcessorInfo": {"SupportedArchitectures": ["x86_64"]}}], "arm64", "InvalidInstanceType"),
    ([{"InstanceType": "t4g.nano"}], "arm64", "UnknownArchitecture"),
    ([{"InstanceType": "t4g.nano", "ProcessorInfo": {"SupportedArchitectures": ["arm64"]}}], None, "UnknownArchitecture"),
])
def test_launch_fails_closed_when_compatibility_cannot_be_confirmed(service, type_response, architecture, code):
    image = {"ImageId": AMI, "State": "available", "RootDeviceType": "ebs", "RootDeviceName": "/dev/xvda"}
    if architecture:
        image["Architecture"] = architecture
    with Stubber(service.ec2) as stub:
        stub.add_response("describe_images", {"Images": [image]}, {"ImageIds": [AMI]})
        stub.add_response("describe_instance_types", {"InstanceTypes": type_response}, {"InstanceTypes": ["t4g.nano"]})
        with pytest.raises(AwsError) as error:
            service.launch({"image_id": AMI, "instance_type": "t4g.nano"})
        assert error.value.code == code
        stub.assert_no_pending_responses()


def test_launch_propagates_instance_type_permission_failure_without_creating_resources(service):
    with Stubber(service.ec2) as stub:
        stub.add_response("describe_images", {"Images": [{"ImageId": AMI, "State": "available", "Architecture": "arm64", "RootDeviceType": "ebs", "RootDeviceName": "/dev/xvda"}]}, {"ImageIds": [AMI]})
        stub.add_client_error("describe_instance_types", "UnauthorizedOperation", "DescribeInstanceTypes denied", expected_params={"InstanceTypes": ["t4g.small"]})
        with pytest.raises(AwsError) as error:
            service.launch({"image_id": AMI, "instance_type": "t4g.small"})
        assert error.value.code == "UnauthorizedOperation"
        stub.assert_no_pending_responses()


def test_launch_rejects_volume_smaller_than_ami_snapshot(service):
    with Stubber(service.ec2) as stub:
        stub.add_response("describe_images", {"Images": [{"ImageId": AMI, "State": "available", "RootDeviceType": "ebs", "RootDeviceName": "/dev/sda1", "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 16}}]}]}, {"ImageIds": [AMI]})
        with pytest.raises(AwsError, match="至少需要 16"):
            service.launch({"image_id": AMI, "volume_size": 8})


OPEN_TOKEN = "stable-open-launch-123"
OPEN_DIGEST = sha256(OPEN_TOKEN.encode()).hexdigest()
OPEN_GROUP_NAME = f"ec2-pilot-open-{OPEN_DIGEST[:32]}"
OPEN_SG = "sg-0123456789abcdef0"
OPEN_SUBNET = "subnet-0123456789abcdef0"
OPEN_VPC = "vpc-0123456789abcdef0"
OPEN_RULES = [
    {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    {"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
]


def open_group():
    return {"GroupId": OPEN_SG, "GroupName": OPEN_GROUP_NAME, "VpcId": OPEN_VPC,
            "Tags": [{"Key": "ManagedBy", "Value": "ec2-panel"}, {"Key": "LaunchToken", "Value": OPEN_DIGEST}]}


def expect_open_launch_image(stub):
    stub.add_response("describe_images", {"Images": [{"ImageId": AMI, "State": "available", "Architecture": "arm64", "RootDeviceType": "ebs", "RootDeviceName": "/dev/xvda"}]}, {"ImageIds": [AMI]})
    stub.add_response("describe_instance_types", {"InstanceTypes": [{"InstanceType": "t4g.micro", "ProcessorInfo": {"SupportedArchitectures": ["arm64"]}}]}, {"InstanceTypes": ["t4g.micro"]})


def expect_open_vpc(stub, subnet=None):
    if subnet:
        stub.add_response("describe_subnets", {"Subnets": [{"SubnetId": subnet, "VpcId": OPEN_VPC}]}, {"SubnetIds": [subnet]})
    else:
        stub.add_response("describe_vpcs", {"Vpcs": [{"VpcId": OPEN_VPC, "IsDefault": True}]}, {"Filters": [{"Name": "is-default", "Values": ["true"]}]})


def expect_open_lookup(stub, groups):
    stub.add_response("describe_security_groups", {"SecurityGroups": groups}, {"Filters": [
        {"Name": "group-name", "Values": [OPEN_GROUP_NAME]}, {"Name": "vpc-id", "Values": [OPEN_VPC]},
    ]})


def expect_open_create(stub, duplicate=False):
    params = {"GroupName": OPEN_GROUP_NAME,
              "Description": "EC2 Pilot launch: allow all inbound IPv4 and IPv6 traffic", "VpcId": OPEN_VPC,
              "TagSpecifications": [{"ResourceType": "security-group", "Tags": open_group()["Tags"]}]}
    if duplicate:
        stub.add_client_error("create_security_group", "InvalidGroup.Duplicate", "already exists", expected_params=params)
    else:
        stub.add_response("create_security_group", {"GroupId": OPEN_SG}, params)


def expect_open_ingress(stub, duplicates=False):
    for permission in OPEN_RULES:
        params = {"GroupId": OPEN_SG, "IpPermissions": [permission]}
        if duplicates:
            stub.add_client_error("authorize_security_group_ingress", "InvalidPermission.Duplicate", "already exists", expected_params=params)
        else:
            stub.add_response("authorize_security_group_ingress", {"Return": True}, params)


def open_launch_params(subnet=None):
    params = {
        "ImageId": AMI, "InstanceType": "t4g.micro", "MinCount": 1, "MaxCount": 1,
        "ClientToken": OPEN_TOKEN, "UserData": "", "SecurityGroupIds": [OPEN_SG],
        "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
        "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 8, "VolumeType": "gp3", "DeleteOnTermination": True, "Encrypted": True}}],
        "TagSpecifications": ANY,
    }
    if subnet:
        params["SubnetId"] = subnet
    return params


@pytest.mark.parametrize("subnet", [None, OPEN_SUBNET])
def test_launch_opens_new_security_group_by_default_in_target_vpc(service, subnet):
    with Stubber(service.ec2) as stub:
        expect_open_launch_image(stub)
        expect_open_vpc(stub, subnet)
        expect_open_lookup(stub, [])
        expect_open_create(stub)
        expect_open_ingress(stub)
        stub.add_response("run_instances", {"Instances": [{"InstanceId": IID}]}, open_launch_params(subnet))
        result = service.launch({"image_id": AMI, "instance_type": "t4g.micro", "operation_token": OPEN_TOKEN, "subnet_id": subnet})
        assert result["instance_ids"] == [IID]
        stub.assert_no_pending_responses()


def test_launch_retry_reuses_group_and_run_parameters_after_failure(service):
    with Stubber(service.ec2) as stub:
        expect_open_launch_image(stub)
        expect_open_vpc(stub)
        expect_open_lookup(stub, [])
        expect_open_create(stub)
        expect_open_ingress(stub)
        stub.add_client_error("run_instances", "InsufficientInstanceCapacity", "capacity unavailable", expected_params=open_launch_params())
        payload = {"image_id": AMI, "instance_type": "t4g.micro", "operation_token": OPEN_TOKEN}
        with pytest.raises(AwsError) as error:
            service.launch(payload)
        assert error.value.code == "InsufficientInstanceCapacity"
        expect_open_launch_image(stub)
        expect_open_vpc(stub)
        expect_open_lookup(stub, [open_group()])
        expect_open_ingress(stub, duplicates=True)
        stub.add_response("run_instances", {"Instances": [{"InstanceId": IID}]}, open_launch_params())
        assert service.launch(payload)["instance_ids"] == [IID]
        stub.assert_no_pending_responses()


def test_launch_handles_concurrent_security_group_creation(service):
    with Stubber(service.ec2) as stub:
        expect_open_launch_image(stub)
        expect_open_vpc(stub)
        expect_open_lookup(stub, [])
        expect_open_create(stub, duplicate=True)
        expect_open_lookup(stub, [open_group()])
        expect_open_ingress(stub, duplicates=True)
        stub.add_response("run_instances", {"Instances": [{"InstanceId": IID}]}, open_launch_params())
        assert service.launch({"image_id": AMI, "instance_type": "t4g.micro", "operation_token": OPEN_TOKEN})["instance_ids"] == [IID]
        stub.assert_no_pending_responses()


def test_launch_requires_subnet_when_no_default_vpc_exists(service):
    with Stubber(service.ec2) as stub:
        expect_open_launch_image(stub)
        stub.add_response("describe_vpcs", {"Vpcs": []}, {"Filters": [{"Name": "is-default", "Values": ["true"]}]})
        with pytest.raises(AwsError, match="请选择一个子网") as error:
            service.launch({"image_id": AMI, "instance_type": "t4g.micro", "operation_token": OPEN_TOKEN})
        assert error.value.code == "DefaultVpcNotFound"
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("bad_tag", ["ManagedBy", "LaunchToken"])
def test_launch_refuses_to_widen_security_group_without_matching_ownership(service, bad_tag):
    group = open_group()
    for tag in group["Tags"]:
        if tag["Key"] == bad_tag:
            tag["Value"] = "unrelated"
    with Stubber(service.ec2) as stub:
        expect_open_launch_image(stub)
        expect_open_vpc(stub)
        expect_open_lookup(stub, [group])
        with pytest.raises(AwsError) as error:
            service.launch({"image_id": AMI, "instance_type": "t4g.micro", "operation_token": OPEN_TOKEN})
        assert error.value.code == "SecurityGroupOwnershipMismatch"
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("failed_rule", [0, 1])
def test_launch_stops_before_instance_when_either_ingress_rule_is_denied(service, failed_rule):
    with Stubber(service.ec2) as stub:
        expect_open_launch_image(stub)
        expect_open_vpc(stub)
        expect_open_lookup(stub, [open_group()])
        for permission in OPEN_RULES[:failed_rule]:
            stub.add_response("authorize_security_group_ingress", {"Return": True}, {"GroupId": OPEN_SG, "IpPermissions": [permission]})
        stub.add_client_error("authorize_security_group_ingress", "UnauthorizedOperation", "denied", expected_params={"GroupId": OPEN_SG, "IpPermissions": [OPEN_RULES[failed_rule]]})
        with pytest.raises(AwsError) as error:
            service.launch({"image_id": AMI, "instance_type": "t4g.micro", "operation_token": OPEN_TOKEN})
        assert error.value.code == "UnauthorizedOperation"
        stub.assert_no_pending_responses()


def test_launch_stops_on_uncertain_ingress_result(service, monkeypatch):
    authorize = Mock(side_effect=ReadTimeoutError(endpoint_url="https://ec2.us-east-1.amazonaws.com"))
    monkeypatch.setattr(service.ec2, "authorize_security_group_ingress", authorize)
    with Stubber(service.ec2) as stub:
        expect_open_launch_image(stub)
        expect_open_vpc(stub)
        expect_open_lookup(stub, [open_group()])
        with pytest.raises(AwsError) as error:
            service.launch({"image_id": AMI, "instance_type": "t4g.micro", "operation_token": OPEN_TOKEN})
        assert error.value.code == "AwsTransportError"
        assert authorize.call_count == 1
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("response", [{"Return": False}, {}])
def test_launch_requires_confirmed_ingress_success(service, response):
    with Stubber(service.ec2) as stub:
        expect_open_launch_image(stub)
        expect_open_vpc(stub)
        expect_open_lookup(stub, [open_group()])
        stub.add_response("authorize_security_group_ingress", response, {"GroupId": OPEN_SG, "IpPermissions": [OPEN_RULES[0]]})
        with pytest.raises(AwsError) as error:
            service.launch({"image_id": AMI, "instance_type": "t4g.micro", "operation_token": OPEN_TOKEN})
        assert error.value.code == "UnconfirmedSecurityGroupRule"
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("options", [
    {"open_all_ports": "true"}, {"security_group_ids": [OPEN_SG]},
])
def test_launch_rejects_conflicting_or_invalid_security_group_options_before_aws(service, options):
    with Stubber(service.ec2):
        with pytest.raises(AwsError) as error:
            service.launch({"image_id": AMI, **options})
        assert error.value.code == "InvalidInput"


def test_launch_explicit_security_group_is_used_without_modifying_its_rules(service):
    with Stubber(service.ec2) as stub:
        expect_open_launch_image(stub)
        stub.add_response("run_instances", {"Instances": [{"InstanceId": IID}]}, open_launch_params(OPEN_SUBNET))
        result = service.launch({"image_id": AMI, "instance_type": "t4g.micro", "operation_token": OPEN_TOKEN,
                                 "open_all_ports": False, "security_group_ids": [OPEN_SG], "subnet_id": OPEN_SUBNET})
        assert result["instance_ids"] == [IID]
        stub.assert_no_pending_responses()


def test_rotate_never_releases_and_reports_previous_address(service, monkeypatch):
    release = Mock(wraps=service.ec2.release_address)
    monkeypatch.setattr(service.ec2, "release_address", release)
    with Stubber(service.ec2) as stub:
        expect_rotate_prelude(stub)
        stub.add_response("associate_address", {"AssociationId": "eipassoc-1123456789abcdef0"}, ASSOCIATE_PARAMS)
        result = service.rotate_ip(IID)
        assert result["public_ip"] == NEW_IP
        assert result["previous_allocation_id"] == OLD
        assert result["previous"] == {"allocation_id": OLD, "association_id": "eipassoc-0123456789abcdef0",
                                      "public_ip": "203.0.113.11", "network_border_group": "ap-southeast-2"}
        assert result["tagged"] is True
        release.assert_not_called()
        stub.assert_no_pending_responses()


def test_before_allocate_runs_after_lookup_and_can_abort_allocation(service, monkeypatch):
    allocate = Mock(wraps=service.ec2.allocate_address)
    monkeypatch.setattr(service.ec2, "allocate_address", allocate)
    seen = []

    def hook(previous):
        seen.append(previous)
        raise RuntimeError("intent could not be stored")

    with Stubber(service.ec2) as stub:
        expect_instance(stub)
        expect_border_group(stub)
        stub.add_response("describe_addresses", {"Addresses": [old_address()]},
                          {"Filters": [{"Name": "network-interface-id", "Values": [ENI]}]})
        with pytest.raises(RuntimeError):
            service.rotate_ip(IID, before_allocate=hook)
        assert seen[0]["allocation_id"] == OLD
        allocate.assert_not_called()
        stub.assert_no_pending_responses()


def test_allocation_falls_back_untagged_only_on_unauthorized(service):
    with Stubber(service.ec2) as stub:
        expect_instance(stub)
        expect_border_group(stub)
        stub.add_response("describe_addresses", {"Addresses": []},
                          {"Filters": [{"Name": "network-interface-id", "Values": [ENI]}]})
        stub.add_client_error("allocate_address", "UnauthorizedOperation", "no CreateTags", expected_params=ALLOCATE_TAGGED)
        stub.add_response("allocate_address", {"AllocationId": NEW, "PublicIp": NEW_IP, "Domain": "vpc"},
                          {"Domain": "vpc", "NetworkBorderGroup": "ap-southeast-2"})
        stub.add_response("associate_address", {"AssociationId": "eipassoc-1123456789abcdef0"}, ASSOCIATE_PARAMS)
        result = service.rotate_ip(IID)
        assert result["tagged"] is False
        assert "带标签的分配请求被拒绝" in result["message"]
        assert "IAM 缺少" not in result["message"]
        stub.assert_no_pending_responses()


def test_allocation_timeout_is_not_retried_untagged(service, monkeypatch):
    allocate = Mock(side_effect=ReadTimeoutError(endpoint_url="https://ec2.ap-southeast-2.amazonaws.com"))
    with Stubber(service.ec2) as stub:
        expect_instance(stub)
        expect_border_group(stub)
        stub.add_response("describe_addresses", {"Addresses": []},
                          {"Filters": [{"Name": "network-interface-id", "Values": [ENI]}]})
        monkeypatch.setattr(service.ec2, "allocate_address", allocate)
        with pytest.raises(AwsError) as error:
            service.rotate_ip(IID)
        assert error.value.code == "AwsTransportError"
        assert allocate.call_count == 1
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("address,expected", [
    ({"AllocationId": OLD, "Domain": "vpc"}, "detached"),
    (old_address(), "stale"),
    (old_address(AssociationId="eipassoc-2223456789abcdef0"), "reused"),
    (old_address(AssociationId="eipassoc-2223456789abcdef0", InstanceId="i-1123456789abcdef0"), "reused"),
])
def test_release_check_compares_recorded_association(service, address, expected):
    with Stubber(service.ec2) as stub:
        stub.add_response("describe_addresses", {"Addresses": [address]}, {"AllocationIds": [OLD]})
        assert service.release_check(OLD, "eipassoc-0123456789abcdef0") == expected
        stub.assert_no_pending_responses()


def test_release_check_gone_unclear_and_transient(service):
    with Stubber(service.ec2) as stub:
        stub.add_client_error("describe_addresses", "InvalidAllocationID.NotFound", "gone", expected_params={"AllocationIds": [OLD]})
        assert service.release_check(OLD, "eipassoc-0123456789abcdef0") == "gone"
        stub.add_response("describe_addresses", {"Addresses": []}, {"AllocationIds": [OLD]})
        assert service.release_check(OLD, "eipassoc-0123456789abcdef0") == "unclear"
        stub.add_client_error("describe_addresses", "RequestLimitExceeded", "slow down", expected_params={"AllocationIds": [OLD]})
        with pytest.raises(AwsError) as error:
            service.release_check(OLD, "eipassoc-0123456789abcdef0")
        assert error.value.code == "RequestLimitExceeded"
        stub.assert_no_pending_responses()


def test_release_address_passes_border_group(service):
    with Stubber(service.ec2) as stub:
        stub.add_response("release_address", {}, {"AllocationId": OLD, "NetworkBorderGroup": "ap-southeast-2"})
        service.release_address(OLD, "ap-southeast-2")
        stub.assert_no_pending_responses()


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
        stub.add_response("allocate_address", {"AllocationId": NEW, "PublicIp": NEW_IP, "Domain": "vpc"}, {**ALLOCATE_TAGGED, "NetworkBorderGroup": "ap-southeast-2-per-1"})
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
