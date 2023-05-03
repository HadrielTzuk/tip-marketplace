from utils import compress_ipv6_address


class Instance(object):
    """
    EC2 Instance data model
    """

    def __init__(self, raw_data):
        self.groups = raw_data.get('Groups')
        self.instances = raw_data.get('Instances')
        self.owner_id = raw_data.get('OwnerId')
        self.reservation_id = raw_data.get('ReservationId')

    def as_json(self):
        return self.instances

    def as_csvs(self):
        return [self.as_csv(instance) for instance in self.instances]

    def as_csv(self, instance_raw_data):
        security_group_name = [group.get('GroupName') for group in instance_raw_data.get('SecurityGroups', {})]
        security_group_name_str = ', '.join(security_group_name)
        return {
            'ID': instance_raw_data.get('InstanceId'),
            'State': instance_raw_data.get('State', {}).get('Name'),
            'Type': instance_raw_data.get('InstanceType'),
            'Availability Zone': instance_raw_data.get('Placement', {}).get('AvailabilityZone'),
            'Public IPv4 DNS': instance_raw_data.get('PublicDnsName'),
            'Public IPv4 address': instance_raw_data.get('PublicIpAddress'),
            'Monitoring': instance_raw_data.get('Monitoring', {}).get('State'),
            'Security group name': security_group_name_str,
            'Key name': instance_raw_data.get('KeyName'),
            'Launch time': instance_raw_data.get('LaunchTime'),
        }


class SecurityGroupIpPermission(object):
    def __init__(self, raw_data=None, to_port=None, from_port=None, ip_protocol=None, ipv4_ranges=None,
                 ipv6_ranges=None):
        self.raw_data = raw_data
        self.from_port = from_port
        self.to_port = to_port
        self.ip_protocol = ip_protocol
        self.ipv4_ranges = ipv4_ranges or []
        self.ipv6_ranges = ipv6_ranges or []

    def contains(self, other) -> bool:
        if isinstance(other, SecurityGroupIpPermission):
            if other.from_port == self.from_port and other.to_port == self.to_port and other.ip_protocol == self.ip_protocol:
                if other.ipv6_ranges:
                    for ipv6 in other.ipv6_ranges:
                        if compress_ipv6_address(ipv6) in self.ipv6_ranges:
                            return True
                if other.ipv4_ranges:
                    for ipv4 in other.ipv4_ranges:
                        if ipv4 in self.ipv4_ranges:
                            return True
                return False

        return False


class SecurityGroup(object):
    """
    EC2 Security Group data model
    """

    class IpPermissionsEgress(SecurityGroupIpPermission):
        def __init__(self, raw_data, to_port=None, from_port=None, ip_protocol=None, ipv4_ranges=None,
                     ipv6_ranges=None):
            super(SecurityGroup.IpPermissionsEgress, self).__init__(raw_data, to_port=to_port, from_port=from_port,
                                                                    ip_protocol=ip_protocol,
                                                                    ipv4_ranges=ipv4_ranges, ipv6_ranges=ipv6_ranges)

    class IpPermissions(SecurityGroupIpPermission):
        def __init__(self, raw_data, to_port=None, from_port=None, ip_protocol=None, ipv4_ranges=None,
                     ipv6_ranges=None):
            super(SecurityGroup.IpPermissions, self).__init__(raw_data, to_port=to_port, from_port=from_port,
                                                              ip_protocol=ip_protocol,
                                                              ipv4_ranges=ipv4_ranges, ipv6_ranges=ipv6_ranges)

    def __init__(self, raw_data, description=None, group_name=None, owner_id=None, ip_permissions=None, group_id=None,
                 ip_permissions_egress=None, tags=None, vpc_id=None):
        self.raw_data = raw_data
        self.description = description
        self.group_name = group_name
        self.owner_id = owner_id
        self.ip_permissions = ip_permissions or []
        self.ip_permissions_egress = ip_permissions_egress or []
        self.group_id = group_id
        self.tags = tags
        self.vpc_id = vpc_id

    def as_json(self):
        return self.raw_data

    def as_csv(self):
        return {
            'Security group ID': self.group_id,
            'Security group name': self.group_name,
            'VPC ID': self.vpc_id,
            'Description': self.description,
            'Owner ID': self.owner_id
        }


class InstanceStatus(object):
    """
    EC2 Instance Status data model
    """

    def __init__(self, raw_data: dict, current_state: str = None, instance_id: str = None, previous_state: str = None):
        self.raw_data = raw_data
        self.current_state = current_state
        self.instance_id = instance_id
        self.previous_state = previous_state

    def as_json(self):
        return {
            'CurrentState': self.current_state,
            'InstanceId': self.instance_id,
            'PreviousState': self.previous_state
        }


class UnknownSecurityGroupIpPermission(SecurityGroupIpPermission):
    """
    Unknown Security Group IP Permission data model
    """

    def __init__(self, raw_data, to_port=None, from_port=None, ip_protocol=None, ipv4_ranges=None, ipv6_ranges=None):
        super(UnknownSecurityGroupIpPermission, self).__init__(raw_data, to_port=to_port, from_port=from_port,
                                                               ip_protocol=ip_protocol,
                                                               ipv4_ranges=ipv4_ranges, ipv6_ranges=ipv6_ranges)


class SnapShot(object):
    """
    EC2 Instance Snapshot data model
    """

    def __init__(self, raw_data: dict, description: str = None, snapshot_id: str = None, volume_id: str = None,
                 owner_id: str = None):
        self.raw_data = raw_data
        self.description = description
        self.volume_id = volume_id
        self.snapshot_id = snapshot_id
        self.owner_id = owner_id

    def as_json(self):
        return self.raw_data

    def as_csv(self):
        return {
            'Description': self.description,
            'Volume Id': self.volume_id,
            'Snapshot Id': self.snapshot_id,
            'Owner ID': self.owner_id
        }
