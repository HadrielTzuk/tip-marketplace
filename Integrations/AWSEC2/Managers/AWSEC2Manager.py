from typing import List
from typing import Optional

import boto3
from boto3.exceptions import botocore

from AWSEC2Parser import AWSEC2Parser
from consts import VALID_STATUS_CODES, DEFAULT_MAX_RESULTS, INVALID_INSTANCE_ID, INCORRECT_INSTANCE_STATE, INVALID_ID, \
    TAG_LIMIT_EXCEEDED, NOT_FOUND, INVALID_PARAMETER_VALUE, INVALID_GROUP_ID, INVALID_SECURITY_GROUP_ERROR_CODES, \
    DUPLICATE_RULE
from datamodels import SecurityGroup
from exceptions import AWSEC2StatusCodeException, AWSEC2IncorrectInstanceStateException, \
    AWSEC2InvalidInstanceIDException, AWSEC2LimitExceededException, \
    AWSEC2InvalidParameterValueException, AWSEC2InvalidSecurityGroupException, AWSEC2UnknownIpPermissions, \
    AWSEC2ValidationException
from utils import remove_empty_kwargs


class AWSEC2Manager(object):
    """
    AWS EC2 Manager
    """

    def __init__(self, aws_access_key, aws_secret_key, aws_default_region):
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.aws_default_region = aws_default_region

        session = boto3.session.Session()

        self.ec2_client = session.client('ec2', aws_access_key_id=self.aws_access_key,
                                         aws_secret_access_key=self.aws_secret_key,
                                         region_name=self.aws_default_region)

        self.parser = AWSEC2Parser()

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        """
        validate client EC2 response status code
        :param response: {Response} client EC2 response
        :param error_msg: {str} Error message
        :return: raise AWSEC2StatusCodeException if status code is not valid
        """
        if response.get('ResponseMetadata', {}).get('HTTPStatusCode') not in VALID_STATUS_CODES:
            raise AWSEC2StatusCodeException(f"{error_msg}. Response: {response}")

    @staticmethod
    def validate_client_error(error, error_msg="An error occurred"):
        if INVALID_INSTANCE_ID in error.response.get('Error', {}).get('Code', ''):
            raise AWSEC2InvalidInstanceIDException(error.response.get('Error', {}).get('Message'))
        if error.response.get('Error', {}).get('Code', '') == INCORRECT_INSTANCE_STATE:
            raise AWSEC2IncorrectInstanceStateException(error.response.get('Error', {}).get('Message'))
        if error.response.get('Error', {}).get('Code', '') in INVALID_SECURITY_GROUP_ERROR_CODES:
            raise AWSEC2InvalidSecurityGroupException(error.response.get('Error', {}).get('Message'))
        if error.response.get('Error', {}).get('Code', '') == INVALID_ID or \
                NOT_FOUND in error.response.get('Error', {}).get('Code', '') or \
                INVALID_GROUP_ID in error.response.get('Error', {}).get('Code', ''):
            raise AWSEC2ValidationException(error.response.get('Error', {}).get('Message'))
        if error.response.get('Error', {}).get('Code', '') == TAG_LIMIT_EXCEEDED:
            raise AWSEC2LimitExceededException(error.response.get('Error', {}).get('Message'))
        if error.response.get('Error', {}).get('Code', '') in [INVALID_PARAMETER_VALUE, DUPLICATE_RULE]:
            raise AWSEC2InvalidParameterValueException(error.response.get('Error', {}).get('Message'))
        raise error

    def test_connectivity(self):
        """
        Test connectivity to AWS EC2 with parameters provided at the integration configuration page on Marketplace tab.
        :return:
                raise boto3.exception.ClientError if connectivity failed
                raise AWSEC2StatusCodeException if connectivity failed to validate status code
        """
        response = self.ec2_client.describe_regions(DryRun=False)
        self.validate_response(response, "Failed to test connectivity with AWS EC2 Service.")

    def list_instances(self, instance_ids: List[str] = None, tag_filters: List = None, max_results: int = None):
        """
        Describes the specified instances or all instances.
        :param instance_ids: {List[str]} One or more instance IDs. Separated by comma
        :param tag_filters: {Dict} The key/value combination of a tag assigned to the resource.
        :param max_results: {int} Specify how many instances to return. Default is 50.
        :return: {List[datamodels.Instance]} List of EC2 data models
        """
        paginator = self.ec2_client.get_paginator("describe_instances")

        pagination_config = {}
        if max_results:
            pagination_config['MaxItems'] = max_results
            pagination_config['PageSize'] = DEFAULT_MAX_RESULTS
            pagination_config['StartingToken'] = None

        kwargs = dict(Filters=tag_filters, InstanceIds=instance_ids, PaginationConfig=pagination_config)

        pages = paginator.paginate(**{k: v for k, v in kwargs.items() if v is not None})

        instances = []
        try:
            for page in pages:
                self.validate_response(page, "Failed to fetch instances from AWS EC2 Service.")
                instances.extend(self.parser.build_instance_objs(page))

            return instances

        except botocore.exceptions.ClientError as error:
            self.validate_client_error(error, "Unable to list instances")

    def start_instances(self, instance_ids: List[str]):
        """
        Starts an Amazon EBS-backed instance that you have previously stopped.
        :param instance_ids: {List[str]} List of AWS EC2 instances ids
        :return: {datamodels.InstanceStatus} EC2 Instance Status data model
                 raise AWSEC2InvalidInstanceIDException if instance id is not valid
                 raise AWSEC2IncorrectInstanceStateException if instance state is not valid
        """
        try:
            response = self.ec2_client.start_instances(InstanceIds=instance_ids)
            self.validate_response(response, "Failed to start instances in AWS EC2 Service.")
            return self.parser.build_instance_status_obj(response=response, action_name='StartingInstances')

        except botocore.exceptions.ClientError as error:
            self.validate_client_error(error, "Unable to start instances")

    def stop_instances(self, instance_ids: List[str], force: bool = False):
        """
        Stop an Amazon EBS-backed instance.
        :param instance_ids: {List[str]} List of AWS EC2 instances ids
        :param force: {bool} Forces the instances to stop. The instances do not have an opportunity to flush file system
         caches or file system metadata.
        :return: {datamodels.InstanceStatus} EC2 Instance Status data model
                 raise AWSEC2InvalidInstanceIDException if instance id is not valid
                 raise AWSEC2IncorrectInstanceStateException if instance state is not valid
        """
        try:
            response = self.ec2_client.stop_instances(InstanceIds=instance_ids, Force=force)
            self.validate_response(response, "Failed to stop instances in AWS EC2 Service.")
            return self.parser.build_instance_status_obj(response=response, action_name='StoppingInstances')

        except botocore.exceptions.ClientError as error:
            self.validate_client_error(error, "Unable to stop instances")

    def list_security_groups(self, security_group_names: List[str] = None, group_ids: List[str] = None,
                             tag_filters: List = None, max_results: int = None):
        """
        Returns the specified security groups or all of your security groups.
        :param group_ids: {List[str]} One or more Security Group IDs.
        :param security_group_names: {List[str]} One or more Security Group namess.
        :param tag_filters: {Dict} The key/value combination of a tag assigned to the resource.
        :param max_results: {int} Specify how many Security Groups to return. Default is 50.
        :return: {List[datamodels.SecurityGroup]} List of EC2 data models
        """
        paginator = self.ec2_client.get_paginator("describe_security_groups")

        pagination_config = {}
        if max_results:
            pagination_config['MaxItems'] = max_results
            pagination_config['PageSize'] = DEFAULT_MAX_RESULTS
            pagination_config['StartingToken'] = None

        kwargs = dict(Filters=tag_filters, GroupNames=security_group_names, GroupIds=group_ids,
                      PaginationConfig=pagination_config,
                      DryRun=False)

        pages = paginator.paginate(**{k: v for k, v in kwargs.items() if v is not None})

        security_groups = []
        for page in pages:
            self.validate_response(page, "Failed to fetch instances from AWS EC2 Service.")
            security_groups.extend(self.parser.build_security_group_objs(page))

        return security_groups

    def terminate_instances(self, instance_ids: List[str]):
        """
        Terminate an Amazon EBS-backed instance.
        :param instance_ids: {List[str]} List of AWS EC2 instances ids
        :return: {datamodels.InstanceStatus} EC2 Instance Status data model
                 raise AWSEC2InvalidInstanceIDException if instance id is not valid
                 raise AWSEC2IncorrectInstanceStateException if instance state is not valid
        """
        try:
            response = self.ec2_client.terminate_instances(InstanceIds=instance_ids)
            self.validate_response(response, "Failed to terminate instances in AWS EC2 Service.")
            return self.parser.build_instance_status_obj(response=response, action_name='TerminatingInstances')

        except botocore.exceptions.ClientError as error:
            self.validate_client_error(error)

    def create_tags(self, resources_id: List[str] = None, tags: List = None):
        """
        Adds or overwrites tags to an AWS resource.
        :param resources_id: {List[str]} One or more resource IDs.
        :param tags: {List[Dict[str, str]]} The key/value combination of a tag to be assigned to the resource.
        for example: [{Owner:TeamA}]
        """
        try:
            response = self.ec2_client.create_tags(Resources=resources_id, Tags=tags)
            self.validate_response(response, "Failed to create tags to AWS EC2 resource.")

        except botocore.exceptions.ClientError as error:
            self.validate_client_error(error, "Unable to create tags")

    def authorize_security_group_egress(self, security_group_id: str, ip_protocol: str = None, from_port: int = None,
                                        to_port: int = None, ip_ranges: str = None, ipv6_ranges=None):
        """
        Adds the specified egress rule to a security group for use with a VPC.
        :param security_group_id: {str} security group ID.
        :param ip_protocol: {str} The IP protocol name.
        :param from_port: {int} The start of port range for the TCP and UDP protocols, or an ICMP type number.
        :param to_port: {int} The start of port range for the TCP and UDP protocols, or an ICMP type number.
        :param ip_ranges: {String} The IPv4 CIDR range. To specify a single IPv4 address, use the /32 prefix length.
        :param ipv6_ranges: {String} The IPv6 CIDR range.  To specify a single IPv6 address, use the /128 prefix length.
        """
        ip_permissions = dict(FromPort=from_port,
                              ToPort=to_port,
                              IpProtocol=ip_protocol,
                              IpRanges=ip_ranges,
                              Ipv6Ranges=ipv6_ranges)

        if ip_ranges:
            ip_permissions['IpRanges'] = [{'CidrIp': ip_ranges}]
        if ipv6_ranges:
            ip_permissions['Ipv6Ranges'] = [{'CidrIpv6': ipv6_ranges}]

        ip_permissions = {k: v for k, v in ip_permissions.items() if v is not None}

        try:
            response = self.ec2_client.authorize_security_group_egress(GroupId=security_group_id,
                                                                       IpPermissions=[ip_permissions])
            self.validate_response(response, "Unable to authorize security group egress")
        except botocore.exceptions.ClientError as error:
            self.validate_client_error(error, "Unable to authorize security group egress")

    def revoke_security_group_egress(self, security_group_id: str, ip_protocol: str, from_port: Optional[int] = None,
                                     to_port: Optional[int] = None, ipv4_ranges_cidr: Optional[str] = None,
                                     ipv6_ranges_cidr: Optional[str] = None):
        """
        Removes the specified egress rules from a security group for EC2-VPC. This action does not apply to security groups for use in EC2-Classic.
        :param security_group_id: {str} The ID of the security group.
        :param ip_protocol: {str} Use a set of IP permissions to specify the protocol name or number
        :param from_port: {int} The start of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 type number.
                A value of -1 indicates all ICMP/ICMPv6 types. If you specify all ICMP/ICMPv6 types, you must specify all codes.
        :param to_port: {int} The end of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 code.
                A value of -1 indicates all ICMP/ICMPv6 codes. If you specify all ICMP/ICMPv6 types, you must specify all codes.
        :param ipv4_ranges_cidr: {str} The IPv4 CIDR range. You can either specify a CIDR range or a source security group, not both.
                To specify a single IPv4 address, use the /32 prefix length.
        :param ipv6_ranges_cidr: {str} The IPv6 CIDR range. You can either specify a CIDR range or a source security group, not both.
                To specify a single IPv6 address, use the /128 prefix length.
        :return
                raise AWSEC2UnknownIpPermissions if IP Permission set is unknown.
        """
        try:
            ip_permissions = {
                'IpProtocol': ip_protocol,
                'ToPort': to_port,
                'FromPort': from_port,
                'IpRanges': [{'CidrIp': ipv4_ranges_cidr}] if ipv4_ranges_cidr else None,
                'Ipv6Ranges': [{'CidrIpv6': ipv6_ranges_cidr}] if ipv6_ranges_cidr else None
            }
            response = self.ec2_client.revoke_security_group_egress(
                GroupId=security_group_id,
                IpPermissions=[remove_empty_kwargs(**ip_permissions)]
            )
            self.validate_response(response, f"Failed to revoke egress rule of security group id {security_group_id}")
            unknown_ip_permissions = self.parser.build_unknown_security_group_ip_permissions_list(response)

            if unknown_ip_permissions:
                raise AWSEC2UnknownIpPermissions(
                    f"Egress rule with provided ip permissions was not found in security group {security_group_id}")

        except botocore.exceptions.ClientError as error:
            self.validate_client_error(error, f"Failed to revoke egress rule of security group id {security_group_id}")

    def describe_security_group(self, security_group_id) -> SecurityGroup:
        """
        Return information about a specific security group
        :param security_group_id: {str} The ID of the security group. Required for security groups in a nondefault VPC.
        :return: {SecurityGroup} Security Group data model
        """
        try:
            response = self.ec2_client.describe_security_groups(GroupIds=[security_group_id])
            self.validate_response(response, f"Failed to get information of security group with id {security_group_id}")
            return self.parser.build_security_group_objs(response)[0]

        except botocore.exceptions.ClientError as error:
            self.validate_client_error(error,
                                       f"Failed to get information of security group with id {security_group_id}")

    def revoke_security_group_ingress(self, security_group_id: str, ip_protocol: str, from_port: Optional[int] = None,
                                      to_port: Optional[int] = None, ipv4_ranges_cidr: Optional[str] = None,
                                      ipv6_ranges_cidr: Optional[str] = None):
        """
        Removes the specified ingress rules from a security group. To remove a rule, the values that you specify (for example, ports)
                must match the existing rule's values exactly.
        :param security_group_id: {str} The ID of the security group.
        :param ip_protocol: {str} Use a set of IP permissions to specify the protocol name or number
        :param from_port: {int} The start of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 type number.
                A value of -1 indicates all ICMP/ICMPv6 types. If you specify all ICMP/ICMPv6 types, you must specify all codes.
        :param to_port: {int} The end of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 code. A value of -1 indicates all ICMP/ICMPv6 codes.
                If you specify all ICMP/ICMPv6 types, you must specify all codes.
        :param ipv4_ranges_cidr: {str} The IPv4 CIDR range. You can either specify a CIDR range or a source security group, not both.
                To specify a single IPv4 address, use the /32 prefix length.
        :param ipv6_ranges_cidr: {str} The IPv6 CIDR range. You can either specify a CIDR range or a source security group, not both.
                To specify a single IPv6 address, use the /128 prefix length.
        :return
                raise AWSEC2UnknownIpPermissions if IP Permission set is unknown.
        """
        try:
            ip_permissions = {
                'IpProtocol': ip_protocol,
                'ToPort': to_port,
                'FromPort': from_port,
                'IpRanges': [{'CidrIp': ipv4_ranges_cidr}] if ipv4_ranges_cidr else None,
                'Ipv6Ranges': [{'CidrIpv6': ipv6_ranges_cidr}] if ipv6_ranges_cidr else None
            }
            response = self.ec2_client.revoke_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[remove_empty_kwargs(**ip_permissions)]
            )
            self.validate_response(response, f"Failed to revoke ingress rule of security group id {security_group_id}")
            unknown_ip_permissions = self.parser.build_unknown_security_group_ip_permissions_list(response)

            if unknown_ip_permissions:
                raise AWSEC2UnknownIpPermissions(
                    f"Ingress rule with provided ip permissions was not found in security group {security_group_id}")

        except botocore.exceptions.ClientError as error:
            self.validate_client_error(error, f"Failed to revoke ingress rule of security group id {security_group_id}")

    def authorize_security_group_ingress(self, security_group_id: str, ip_protocol: str = None,
                                         from_port: Optional[int] = None,
                                         to_port: Optional[int] = None, ipv4_ranges_cidr: Optional[str] = None,
                                         ipv6_ranges_cidr: Optional[str] = None):
        """
        Adds the specified ingress rules to a security group.
        An inbound rule permits instances to receive traffic from the specified IPv4 or IPv6 CIDR address ranges,
        or from the instances associated with the specified destination security groups.
        You specify a protocol for each rule (for example, TCP). For TCP and UDP, you must also specify the destination port or port range.
        For ICMP/ICMPv6, you must also specify the ICMP/ICMPv6 type and code. You can use -1 to mean all types or all codes.
        Rule changes are propagated to instances within the security group as quickly as possible. However, a small delay might occur.
        :param security_group_id:  {str} The ID of the security group.
        :param ip_protocol: {str} Use a set of IP permissions to specify the protocol name or number
        :param from_port: {int} The start of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 type number.
                                A value of -1 indicates all ICMP/ICMPv6 types. If you specify all ICMP/ICMPv6 types, you must specify all codes.
        :param to_port: {int} The end of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 code. A value of -1 indicates all ICMP/ICMPv6 codes.
                                If you specify all ICMP/ICMPv6 types, you must specify all codes.
        :param ipv4_ranges_cidr: {str} The IPv4 CIDR range. You can either specify a CIDR range or a source security group, not both.
                To specify a single IPv4 address, use the /32 prefix length.
        :param ipv6_ranges_cidr: {str} The IPv6 CIDR range. You can either specify a CIDR range or a source security group, not both.
                To specify a single IPv6 address, use the /128 prefix length.
        """
        try:
            ip_permissions = {
                'IpProtocol': ip_protocol,
                'ToPort': to_port,
                'FromPort': from_port,
                'IpRanges': [{'CidrIp': ipv4_ranges_cidr}] if ipv4_ranges_cidr else None,
                'Ipv6Ranges': [{'CidrIpv6': ipv6_ranges_cidr}] if ipv6_ranges_cidr else None
            }

            response = self.ec2_client.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[remove_empty_kwargs(**ip_permissions)]
            )

            self.validate_response(response,
                                   f"Failed to authorize security group ingress rule of security group id {security_group_id}")
        except botocore.exceptions.ClientError as error:
            self.validate_client_error(error,
                                       f"Failed to authorize security group ingress rule of security group id {security_group_id}")

    def create_snapshots(self, instance_id: str, description: str):

        try:
            response = self.ec2_client.create_snapshots(Description=description,
                                                        InstanceSpecification={"InstanceId": instance_id})
            self.validate_response(response, "Failed to create snapshot in AWS EC2 Service.")
            return self.parser.build_snapshot_obj(response=response)

        except botocore.exceptions.ClientError as error:
            self.validate_client_error(error)
