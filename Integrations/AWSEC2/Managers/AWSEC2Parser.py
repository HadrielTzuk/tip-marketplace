from consts import RESERVATIONS, SECURITY_GROUP
from datamodels import Instance, InstanceStatus, SecurityGroup, UnknownSecurityGroupIpPermission, SnapShot


class AWSEC2Parser(object):
    """
    AWS EC2 Transformation Layer.
    """

    @staticmethod
    def build_instance_objs(instances_list):
        """
        Return list of EC2 instance objects
        :param instances_list: {dict} list of raw data of instances
        :return: {list} datamodels.Instance objects
        """
        instances_raw_list = instances_list.get(RESERVATIONS, [])
        instances = []
        for instance in instances_raw_list:
            instances.append(AWSEC2Parser.build_instance_obj(instance))
        return instances

    @staticmethod
    def build_instance_obj(instance):
        return Instance(raw_data=instance)

    @staticmethod
    def build_security_group_objs(security_groups):
        """
        Return list of EC2 instance objects
        :param instances_list: {dict} list of raw data of instances
        :return: {list} datamodels.Instance objects
        """
        security_groups_raw_list = security_groups.get(SECURITY_GROUP, [])
        security_groups = []
        for security_group in security_groups_raw_list:
            security_groups.append(AWSEC2Parser.build_security_group_obj(security_group))
        return security_groups

    @staticmethod
    def build_security_group_obj(security_group):
        return SecurityGroup(
            raw_data=security_group,
            description=security_group.get('Description'),
            group_name=security_group.get('GroupName'),
            owner_id=security_group.get("OwnerId"),
            ip_permissions=[AWSEC2Parser.build_security_group_ip_permission(ip_permission) for ip_permission in
                            security_group.get("IpPermissions")],
            ip_permissions_egress=[AWSEC2Parser.build_security_group_ip_permission_egress(ip_permission_egress) for
                                   ip_permission_egress in security_group.get("IpPermissionsEgress")],
            group_id=security_group.get("GroupId"),
            tags=security_group.get("Tags"),
            vpc_id=security_group.get("VpcId")
        )

    @staticmethod
    def build_instance_status_objs(response):
        instances = []
        starting_instances = response.get('StartingInstances', {})
        for instance in starting_instances:
            instances.append(AWSEC2Parser.build_instance_status_obj(instance))
        return instances

    @staticmethod
    def build_instance_status_obj(response, action_name):
        action_instances = response.get(action_name, [])
        if not action_instances:
            return None
        raw_data = action_instances[0]
        return InstanceStatus(raw_data=raw_data,
                              current_state=raw_data.get('CurrentState', {}).get('Name', ''),
                              instance_id=raw_data.get('InstanceId', ''),
                              previous_state=raw_data.get('PreviousState', {}).get('Name', ''))

    @staticmethod
    def build_unknown_security_group_ip_permissions_list(response):
        if response.get("UnknownIpPermissions"):
            return [AWSEC2Parser.build_unknown_security_group_ip_permission(ip_permission) for ip_permission in
                    response.get("UnknownIpPermissions")]

    @staticmethod
    def build_unknown_security_group_ip_permission(response):
        return UnknownSecurityGroupIpPermission(raw_data=response,
                                                from_port=response.get("FromPort"),
                                                to_port=response.get("ToPort"),
                                                ip_protocol=response.get("IpProtocol"),
                                                ipv4_ranges=response.get("IpRanges"),
                                                ipv6_ranges=response.get("Ipv6Ranges"))

    @staticmethod
    def build_security_group_ip_permission(response):
        return SecurityGroup.IpPermissions(raw_data=response,
                                           from_port=response.get("FromPort"),
                                           to_port=response.get("ToPort"),
                                           ip_protocol=response.get("IpProtocol"),
                                           ipv4_ranges=[ip_range.get("CidrIp") for ip_range in
                                                        response.get("IpRanges")],
                                           ipv6_ranges=[ipv6_range.get("CidrIpv6") for ipv6_range in
                                                        response.get("Ipv6Ranges")])

    @staticmethod
    def build_security_group_ip_permission_egress(response):
        return SecurityGroup.IpPermissionsEgress(raw_data=response,
                                                 from_port=response.get("FromPort"),
                                                 to_port=response.get("ToPort"),
                                                 ip_protocol=response.get("IpProtocol"),
                                                 ipv4_ranges=[ip_range.get("CidrIp") for ip_range in
                                                              response.get("IpRanges")],
                                                 ipv6_ranges=[ipv6_range.get("CidrIpv6") for ipv6_range in
                                                              response.get("Ipv6Ranges")])

    @staticmethod
    def build_snapshot_obj(response):
        return SnapShot(
            raw_data=response.get("Snapshots", {})
        )
