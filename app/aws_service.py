"""Small, direct AWS adapter. No AWS Account/Organizations/contact API is used.

Credentials are supplied explicitly and never included in returned values or logs.
EC2 calls deliberately have no automatic retry: allocating an EIP is not idempotent.
The browser's operation token makes an explicitly retried launch idempotent.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import re
from typing import Any
from uuid import uuid4

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


class AwsError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def _id(value: Any, prefix: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(rf"{prefix}-(?:[0-9a-f]{{8}}|[0-9a-f]{{17}})", value):
        raise AwsError("InvalidInput", f"无效的 {prefix} 资源 ID。")
    return value


def _user_data(content: Any) -> bytes:
    if not isinstance(content, str):
        raise AwsError("InvalidInput", "开机脚本必须是文本。")
    encoded = content.encode("utf-8")
    if len(encoded) > 16384:
        raise AwsError("InvalidInput", "开机脚本超过 EC2 的 16 KiB 原始 UTF-8 大小限制。")
    return encoded


def _name(resource: dict, fallback: str = "") -> str:
    return next((tag.get("Value", "") for tag in resource.get("Tags", []) if tag.get("Key") == "Name"), fallback)


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.replace(tzinfo=value.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat()
    return str(value) if value else None


class AwsService:
    def __init__(self, credentials: dict, region: str):
        if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-\d", region):
            raise AwsError("InvalidInput", "AWS 区域格式无效，例如 us-east-1。")
        key = credentials.get("access_key_id", "")
        secret = credentials.get("secret_access_key", "")
        token = credentials.get("session_token") or None
        if not isinstance(key, str) or not isinstance(secret, str) or not key.strip() or not secret.strip():
            raise AwsError("InvalidInput", "Access Key ID 和 Secret Access Key 不能为空。")
        self.region = region
        self._secrets = tuple(x for x in (key, secret, token) if isinstance(x, str) and x)
        self._session = boto3.Session(
            aws_access_key_id=key,
            aws_secret_access_key=secret,
            aws_session_token=token,
            region_name=region,
        )
        config = Config(connect_timeout=5, read_timeout=20, retries={"mode": "standard", "total_max_attempts": 1})
        self.ec2 = self._session.client("ec2", region_name=region, config=config)
        self.sts = self._session.client("sts", region_name=region, config=config)

    def _clean_message(self, message: str) -> str:
        for secret in self._secrets:
            message = message.replace(secret, "[redacted]")
        message = re.sub(r"[\x00-\x1f\x7f]", " ", message)
        # AWS can append a very long encoded authorization failure message.
        return message.split("Encoded authorization failure message:", 1)[0][:1000]

    def _call(self, method, **kwargs):
        try:
            return method(**kwargs)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = re.sub(r"[^A-Za-z0-9_.-]", "", str(error.get("Code", "AwsError")))[:100]
            raise AwsError(code, self._clean_message(str(error.get("Message", "AWS 拒绝了请求。")))) from None
        except BotoCoreError:
            # Do not expose signed request details, proxy URLs, or supplied data.
            raise AwsError("AwsTransportError", "AWS 请求未获得确定响应。请先刷新 AWS 资源状态，再决定是否重试。") from None

    def _all(self, operation: str, field: str, **kwargs) -> list:
        items = []
        while True:
            response = self._call(getattr(self.ec2, operation), **kwargs)
            items.extend(response.get(field, []))
            token = response.get("NextToken")
            if not token:
                return items
            kwargs["NextToken"] = token

    def validate(self) -> dict:
        """STS authentication succeeds without querying restricted contact data."""
        identity = self._call(self.sts.get_caller_identity)
        return {"aws_account_id": identity["Account"], "arn": identity["Arn"]}

    def _instance(self, instance_id: str) -> dict:
        instance_id = _id(instance_id, "i")
        result = self._call(self.ec2.describe_instances, InstanceIds=[instance_id])
        matches = [i for r in result.get("Reservations", []) for i in r.get("Instances", []) if i.get("InstanceId") == instance_id]
        if len(matches) != 1:
            raise AwsError("InstanceNotFound", "在所选账号与区域内未找到唯一的目标实例。")
        return matches[0]

    def instances(self) -> list[dict]:
        reservations = self._all("describe_instances", "Reservations")
        instances = []
        for reservation in reservations:
            for item in reservation.get("Instances", []):
                instances.append({
                    "id": item["InstanceId"], "name": _name(item, item["InstanceId"]),
                    "state": item.get("State", {}).get("Name", "unknown"),
                    "instance_type": item.get("InstanceType", ""),
                    "public_ip": item.get("PublicIpAddress"), "private_ip": item.get("PrivateIpAddress"),
                    "availability_zone": item.get("Placement", {}).get("AvailabilityZone", ""),
                    "image_id": item.get("ImageId", ""), "launch_time": _iso(item.get("LaunchTime")),
                    "key_name": item.get("KeyName"), "subnet_id": item.get("SubnetId"),
                    "security_group_ids": [g["GroupId"] for g in item.get("SecurityGroups", [])],
                })
        return sorted(instances, key=lambda item: (item["name"].lower(), item["id"]))

    def resources(self) -> dict:
        images = self._all("describe_images", "Images", Owners=["amazon"], Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-kernel-*-x86_64", "al2023-ami-2023.*-kernel-*-arm64"]},
            {"Name": "architecture", "Values": ["x86_64", "arm64"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "root-device-type", "Values": ["ebs"]},
        ])
        subnets = self._all("describe_subnets", "Subnets")
        groups = self._all("describe_security_groups", "SecurityGroups")
        keys = self._call(self.ec2.describe_key_pairs).get("KeyPairs", [])
        # Keep each architecture's newest images; a newer x86 release must not
        # push every ARM image out of the suggestions.
        latest = []
        for architecture in ("x86_64", "arm64"):
            matching = [item for item in images if item.get("Architecture") == architecture]
            latest.extend(sorted(matching, key=lambda item: item.get("CreationDate", ""), reverse=True)[:5])
        return {
            "images": [{"id": i["ImageId"], "name": i.get("Name", i["ImageId"]), "description": i.get("Description", ""), "architecture": i.get("Architecture"), "root_device_name": i.get("RootDeviceName")} for i in latest],
            "subnets": [{"id": s["SubnetId"], "name": _name(s, s["SubnetId"]), "vpc_id": s.get("VpcId"), "availability_zone": s.get("AvailabilityZone"), "map_public_ip_on_launch": s.get("MapPublicIpOnLaunch", False)} for s in subnets],
            "security_groups": [{"id": g["GroupId"], "name": g.get("GroupName", ""), "vpc_id": g.get("VpcId"), "description": g.get("Description", "")} for g in groups],
            "key_pairs": [{"id": k.get("KeyPairId"), "name": k["KeyName"]} for k in keys],
        }

    def _open_security_group(self, subnet: str | None, token: str) -> str:
        """Create/reuse only this launch's group; never widen a supplied group."""
        if subnet:
            subnets = self._call(self.ec2.describe_subnets, SubnetIds=[subnet]).get("Subnets", [])
            if len(subnets) != 1 or subnets[0].get("SubnetId") != subnet:
                raise AwsError("InvalidSubnet", "无法确认所选子网及其 VPC，未创建安全组。")
            vpc_id = _id(subnets[0].get("VpcId"), "vpc")
        else:
            vpcs = self._all("describe_vpcs", "Vpcs", Filters=[{"Name": "is-default", "Values": ["true"]}])
            if len(vpcs) != 1 or not vpcs[0].get("IsDefault"):
                raise AwsError("DefaultVpcNotFound", "所选区域没有唯一的默认 VPC，请选择一个子网后重试。")
            vpc_id = _id(vpcs[0].get("VpcId"), "vpc")
        digest = sha256(token.encode("utf-8")).hexdigest()
        group_name = f"ec2-pilot-open-{digest[:32]}"

        def lookup() -> str | None:
            matches = self._all("describe_security_groups", "SecurityGroups", Filters=[
                {"Name": "group-name", "Values": [group_name]},
                {"Name": "vpc-id", "Values": [vpc_id]},
            ])
            if not matches:
                return None
            if len(matches) != 1:
                raise AwsError("AmbiguousSecurityGroup", "无法确认本次创建操作的唯一安全组，未修改入站规则。")
            group = matches[0]
            tags = {tag.get("Key"): tag.get("Value") for tag in group.get("Tags", [])}
            if (group.get("GroupName") != group_name or group.get("VpcId") != vpc_id
                    or tags.get("ManagedBy") != "ec2-panel" or tags.get("LaunchToken") != digest):
                raise AwsError("SecurityGroupOwnershipMismatch", "同名安全组不属于本次创建操作，未修改其规则。")
            return _id(group.get("GroupId"), "sg")

        group_id = lookup()
        if not group_id:
            try:
                created = self._call(self.ec2.create_security_group, GroupName=group_name,
                    Description="EC2 Pilot launch: allow all inbound IPv4 and IPv6 traffic", VpcId=vpc_id,
                    TagSpecifications=[{"ResourceType": "security-group", "Tags": [
                        {"Key": "ManagedBy", "Value": "ec2-panel"}, {"Key": "LaunchToken", "Value": digest},
                    ]}])
                group_id = _id(created.get("GroupId"), "sg")
            except AwsError as exc:
                if exc.code != "InvalidGroup.Duplicate":
                    raise
                # A concurrent retry may have created the deterministic name.
                group_id = lookup()
                if not group_id:
                    raise AwsError("SecurityGroupNotFound", "安全组刚被创建但尚无法确认，请用同一创建操作重试。") from None
        for permission in (
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
        ):
            try:
                authorized = self._call(self.ec2.authorize_security_group_ingress, GroupId=group_id, IpPermissions=[permission])
                if authorized.get("Return") is not True:
                    raise AwsError("UnconfirmedSecurityGroupRule", "AWS 未确认安全组入站规则已生效，尚未创建实例。请用同一创建操作重试。")
            except AwsError as exc:
                if exc.code != "InvalidPermission.Duplicate":
                    raise
        # Keep the group if RunInstances later fails: the same launch token must
        # always reuse the same SecurityGroupIds for AWS client-token idempotency.
        return group_id

    def launch(self, payload: dict) -> dict:
        image_id = _id(payload.get("image_id"), "ami")
        instance_type = payload.get("instance_type", "t3.micro")
        if not isinstance(instance_type, str) or not re.fullmatch(r"[a-z][a-z0-9-]*\.[a-z0-9]+", instance_type):
            raise AwsError("InvalidInput", "实例规格格式无效。")
        script = payload.get("user_data") or ""
        _user_data(script)
        volume_size = payload.get("volume_size", 8)
        if not isinstance(volume_size, int) or isinstance(volume_size, bool) or not 8 <= volume_size <= 1024:
            raise AwsError("InvalidInput", "根磁盘大小必须为 8–1024 GiB 的整数。")
        name = payload.get("name") or "EC2 Panel"
        if not isinstance(name, str) or len(name) > 256:
            raise AwsError("InvalidInput", "实例名称最多 256 个字符。")
        token = payload.get("operation_token") or str(uuid4())
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", token):
            raise AwsError("InvalidInput", "创建操作标识无效。")
        groups = payload.get("security_group_ids") or []
        if not isinstance(groups, list) or len(groups) > 16:
            raise AwsError("InvalidInput", "安全组必须是 ID 列表。")
        groups = [_id(group, "sg") for group in groups]
        open_all_ports = payload.get("open_all_ports", True)
        if not isinstance(open_all_ports, bool):
            raise AwsError("InvalidInput", "open_all_ports 必须是布尔值。")
        if open_all_ports and groups:
            raise AwsError("InvalidInput", "自动全部开放与手动指定安全组不能同时使用，请关闭自动全部开放或清空安全组。")
        subnet = payload.get("subnet_id")
        if subnet:
            subnet = _id(subnet, "subnet")
        images = self._call(self.ec2.describe_images, ImageIds=[image_id]).get("Images", [])
        if len(images) != 1 or images[0].get("State") != "available":
            raise AwsError("InvalidImage", "AMI 不存在、不可用，或不属于所选区域。")
        image = images[0]
        root_device = image.get("RootDeviceName")
        if image.get("RootDeviceType") != "ebs" or not root_device:
            raise AwsError("UnsupportedImage", "简易面板仅支持具有 EBS 根磁盘的 AMI。")
        minimum = next((m.get("Ebs", {}).get("VolumeSize", 0) for m in image.get("BlockDeviceMappings", []) if m.get("DeviceName") == root_device), 0)
        if volume_size < minimum:
            raise AwsError("InvalidInput", f"该 AMI 的根磁盘至少需要 {minimum} GiB。")
        instance_types = self._call(self.ec2.describe_instance_types, InstanceTypes=[instance_type]).get("InstanceTypes", [])
        if len(instance_types) != 1 or instance_types[0].get("InstanceType") != instance_type:
            raise AwsError("InvalidInstanceType", f"在所选区域无法确认实例规格 {instance_type}。")
        supported = instance_types[0].get("ProcessorInfo", {}).get("SupportedArchitectures", [])
        architecture = image.get("Architecture")
        if not architecture or not supported:
            raise AwsError("UnknownArchitecture", "无法确认 AMI 或实例规格的处理器架构，请选择其他镜像或规格。")
        if architecture not in supported:
            raise AwsError("ImageArchitectureMismatch", f"实例规格 {instance_type} 支持 {', '.join(supported)}，所选 AMI 为 {architecture}；请选择兼容的镜像。")
        if open_all_ports:
            groups = [self._open_security_group(subnet, token)]
        request = {
            "ImageId": image_id, "InstanceType": instance_type,
            "MinCount": 1, "MaxCount": 1, "ClientToken": token,
            # Boto3 RunInstances automatically base64 encodes this raw string.
            "UserData": script,
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
            "BlockDeviceMappings": [{"DeviceName": root_device, "Ebs": {"VolumeSize": volume_size, "VolumeType": "gp3", "DeleteOnTermination": True, "Encrypted": True}}],
            "TagSpecifications": [{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}, {"Key": "ManagedBy", "Value": "ec2-panel"}]}],
        }
        if subnet:
            request["SubnetId"] = subnet
        if groups:
            request["SecurityGroupIds"] = groups
        if payload.get("key_name"):
            request["KeyName"] = payload["key_name"]
        response = self._call(self.ec2.run_instances, **request)
        return {"instance_ids": [i["InstanceId"] for i in response.get("Instances", [])], "message": "EC2 创建请求已提交。公网 IP 由所选子网配置决定；实例和磁盘可能消耗赠金或产生费用。"}

    def start(self, instance_id: str) -> dict:
        instance = self._instance(instance_id)
        if instance.get("State", {}).get("Name") != "stopped":
            raise AwsError("IncorrectInstanceState", "仅已停止的实例可开机，请刷新实例状态。")
        self._call(self.ec2.start_instances, InstanceIds=[instance_id])
        return {"message": "开机请求已提交，请刷新查看状态。"}

    def stop(self, instance_id: str) -> dict:
        instance = self._instance(instance_id)
        if instance.get("State", {}).get("Name") != "running":
            raise AwsError("IncorrectInstanceState", "仅运行中的实例可停止，请刷新实例状态。")
        self._call(self.ec2.stop_instances, InstanceIds=[instance_id])
        return {"message": "停止请求已提交。EBS 磁盘与保留的弹性公网 IP 仍可能计费。"}

    def reboot(self, instance_id: str) -> dict:
        instance = self._instance(instance_id)
        if instance.get("State", {}).get("Name") != "running":
            raise AwsError("IncorrectInstanceState", "仅运行中的实例可重启，请刷新实例状态。")
        self._call(self.ec2.reboot_instances, InstanceIds=[instance_id])
        return {"message": "重启请求已提交，连接将短暂中断。"}

    def set_user_data(self, instance_id: str, content: str) -> dict:
        raw = _user_data(content)
        instance = self._instance(instance_id)
        if instance.get("State", {}).get("Name") != "stopped":
            raise AwsError("IncorrectInstanceState", "修改开机脚本前必须先停止实例，并等待状态变为 stopped。")
        # This field is a modeled blob. Botocore encodes these bytes exactly once.
        self._call(self.ec2.modify_instance_attribute, InstanceId=instance_id, UserData={"Value": raw})
        return {"message": "User data 已更新。既有实例的 cloud-init 默认不会因此重新执行；是否执行取决于镜像和系统配置。"}

    @staticmethod
    def _unassociated(address: dict) -> bool:
        return not any(address.get(field) for field in ("AssociationId", "NetworkInterfaceId", "InstanceId"))

    def rotate_ip(self, instance_id: str, release_previous: bool = False) -> dict:
        if not isinstance(release_previous, bool):
            raise AwsError("InvalidInput", "release_previous 必须是布尔值。")
        instance = self._instance(instance_id)
        if instance.get("State", {}).get("Name") not in ("running", "stopped"):
            raise AwsError("IncorrectInstanceState", "请等待实例进入 running 或 stopped 状态后再更换 IP。")
        primary_enis = [eni for eni in instance.get("NetworkInterfaces", []) if eni.get("Attachment", {}).get("DeviceIndex") == 0]
        if len(primary_enis) != 1:
            raise AwsError("AmbiguousNetworkInterface", "无法确定唯一主网卡；请在 AWS 控制台手动选择网卡进行操作。")
        eni = primary_enis[0]
        eni_id = _id(eni.get("NetworkInterfaceId"), "eni")
        primary_ips = [ip.get("PrivateIpAddress") for ip in eni.get("PrivateIpAddresses", []) if ip.get("Primary")]
        if len(primary_ips) != 1 or not primary_ips[0] or eni.get("PrivateIpAddress") != primary_ips[0]:
            raise AwsError("AmbiguousPrivateAddress", "无法确认主网卡的主私网 IP，未分配任何新地址。")
        private_ip = primary_ips[0]
        zone_name = instance.get("Placement", {}).get("AvailabilityZone")
        if not zone_name:
            raise AwsError("UnknownNetworkBorderGroup", "无法确定实例可用区，未分配任何新地址。")
        zones = self._call(self.ec2.describe_availability_zones, ZoneNames=[zone_name]).get("AvailabilityZones", [])
        if len(zones) != 1 or zones[0].get("ZoneName") != zone_name or not zones[0].get("NetworkBorderGroup"):
            raise AwsError("UnknownNetworkBorderGroup", "无法确认实例所在网络边界组，未分配任何新地址。")
        if zones[0].get("ZoneType") == "wavelength-zone":
            raise AwsError("UnsupportedZone", "简易面板暂不支持 Wavelength 区域的运营商 IP，请在 AWS 控制台管理。")
        border_group = zones[0]["NetworkBorderGroup"]
        addresses = self._call(self.ec2.describe_addresses, Filters=[{"Name": "network-interface-id", "Values": [eni_id]}]).get("Addresses", [])
        previous_matches = [a for a in addresses if a.get("NetworkInterfaceId") == eni_id and a.get("PrivateIpAddress") == private_ip]
        if len(previous_matches) > 1:
            raise AwsError("AmbiguousPreviousAddress", "无法确定原弹性 IP，未分配新地址。")
        previous = previous_matches[0] if previous_matches else None
        if previous and (not previous.get("AllocationId") or not previous.get("AssociationId") or previous.get("InstanceId") != instance_id):
            raise AwsError("AmbiguousPreviousAddress", "原弹性 IP 的实例归属不明确，未分配新地址。")
        allocated = self._call(self.ec2.allocate_address, Domain="vpc", NetworkBorderGroup=border_group)
        allocation_id = allocated.get("AllocationId")
        if not allocation_id or not allocated.get("PublicIp"):
            raise AwsError("IncompleteAllocation", "AWS 分配地址响应不完整，请先到控制台核对弹性 IP，避免重复分配。")
        try:
            self._call(self.ec2.associate_address, AllocationId=allocation_id,
                       NetworkInterfaceId=eni_id, PrivateIpAddress=private_ip, AllowReassociation=False)
        except AwsError as exc:
            # A timeout/5xx may mean the association succeeded. Never release after
            # an ambiguous outcome, even if a subsequent read looks unassociated.
            definite_rejection = exc.code in {
                "UnauthorizedOperation", "AuthFailure", "InvalidAllocationID.NotFound",
                "InvalidNetworkInterfaceID.NotFound", "InvalidParameterValue",
                "InvalidParameterCombination", "IncorrectInstanceState",
            }
            cleaned = False
            if definite_rejection:
                try:
                    current = self._call(self.ec2.describe_addresses, AllocationIds=[allocation_id]).get("Addresses", [])
                    if len(current) == 1 and current[0].get("AllocationId") == allocation_id and self._unassociated(current[0]):
                        self._call(self.ec2.release_address, AllocationId=allocation_id, NetworkBorderGroup=border_group)
                        cleaned = True
                except AwsError:
                    pass
            note = "新分配且未绑定的地址已回收。" if cleaned else f"新地址 {allocated['PublicIp']}（{allocation_id}）已保留，可能计费；请先在 AWS 核对关联状态，勿直接重试。"
            raise AwsError(exc.code, f"{exc.message} {note}") from None
        message = "新弹性公网 IP 已绑定至主网卡。公网 IPv4 可能消耗赠金或产生费用。"
        previous_id = previous.get("AllocationId") if previous else None
        if previous_id and release_previous:
            try:
                current = self._call(self.ec2.describe_addresses, AllocationIds=[previous_id]).get("Addresses", [])
                if len(current) == 1 and current[0].get("AllocationId") == previous_id and self._unassociated(current[0]):
                    self._call(self.ec2.release_address, AllocationId=previous_id, NetworkBorderGroup=previous.get("NetworkBorderGroup") or border_group)
                    message += " 原弹性 IP 已释放，无法保证再次取回。"
                else:
                    message += " 原弹性 IP 当前仍有关联或状态不明确，已保留；请在 AWS 核对，可能继续计费。"
            except AwsError as exc:
                message += f" 原弹性 IP 释放失败（{exc.code}），已保留并可能继续计费，请在 AWS 核对。"
        elif previous_id:
            message += " 原弹性 IP 已保留但不再绑定此实例，可能继续计费。"
        else:
            message += " 若原 IP 为自动分配的公网地址，它将被 AWS 释放。"
        return {"public_ip": allocated["PublicIp"], "allocation_id": allocation_id,
                "previous_allocation_id": previous_id, "message": message}
