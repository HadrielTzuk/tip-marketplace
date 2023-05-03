from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from AWSEC2Manager import AWSEC2Manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from consts import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, AUTHORIZE_SECURITY_GROUP_EGRESS
from utils import load_csv_to_list, compress_ipv6_address
from exceptions import AWSEC2ValidationException, AWSEC2InvalidParameterValueException, AWSEC2InvalidSecurityGroupException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, AUTHORIZE_SECURITY_GROUP_EGRESS)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    aws_access_key = extract_configuration_param(siemplify,
                                                 provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Access Key ID",
                                                 is_mandatory=True)

    aws_secret_key = extract_configuration_param(siemplify,
                                                 provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Secret Key",
                                                 is_mandatory=True)

    aws_default_region = extract_configuration_param(siemplify,
                                                     provider_name=INTEGRATION_NAME,
                                                     param_name="AWS Default Region",
                                                     is_mandatory=True)

    # Params
    security_group_ids = extract_action_param(siemplify,
                                              param_name="Security Group IDs",
                                              is_mandatory=False,
                                              print_value=True)

    ip_protocol = extract_action_param(siemplify,
                                       param_name="IP Protocol",
                                       is_mandatory=False,
                                       print_value=True)

    ip_ranges = extract_action_param(siemplify,
                                     param_name="IP Ranges - CidrIP",
                                     is_mandatory=False,
                                     print_value=True)

    ipv6_ranges = extract_action_param(siemplify,
                                       param_name="IPv6 Ranges - CidrIP",
                                       is_mandatory=False,
                                       print_value=True)

    result_value = False
    output_message = ""

    try:
        from_port = extract_action_param(siemplify,
                                         param_name="From Port",
                                         input_type=int,
                                         is_mandatory=False,
                                         print_value=True)

        to_port = extract_action_param(siemplify,
                                       param_name="To Port",
                                       input_type=int,
                                       is_mandatory=False,
                                       print_value=True)

        if ip_protocol not in ['tcp', 'udp', 'icmp']:
            siemplify.LOGGER.info("Port selection is possible only when tcp, udp or icmp rules are added, otherwise,"
                                  " all-ports will be set")
            from_port = None
            to_port = None
            ip_protocol = '-1'

        if ipv6_ranges:
            ipv6_ranges = compress_ipv6_address(ipv6_ranges)

        manager = AWSEC2Manager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                aws_default_region=aws_default_region)

        manager.test_connectivity()

        # Split the security group ids if exists
        security_group_ids_list = load_csv_to_list(security_group_ids, "Security Group IDs", ',')

        success_security_group = []
        invalid_permission_security_group = []
        already_exists_rules = []
        not_found_ids = []

        siemplify.LOGGER.info("Starting to authorize security group egress")
        for security_group_id in security_group_ids_list:
            try:
                siemplify.LOGGER.info(f"Authorize security group egress to security group with id: {security_group_id}")
                manager.authorize_security_group_egress(security_group_id=security_group_id,
                                                        ip_protocol=ip_protocol,
                                                        from_port=from_port,
                                                        to_port=to_port,
                                                        ip_ranges=ip_ranges,
                                                        ipv6_ranges=ipv6_ranges)

                success_security_group.append(security_group_id)

            except (AWSEC2ValidationException, AWSEC2InvalidSecurityGroupException) as error:
                siemplify.LOGGER.exception(error)
                not_found_ids.append(security_group_id)

            except AWSEC2InvalidParameterValueException as error:
                siemplify.LOGGER.exception(error)
                invalid_permission_security_group.append(security_group_id)

        if success_security_group:
            #  Check if rule was authorized
            succeed_groups = []
            failed_groups = []
            for security_group_id in success_security_group:
                security_group_egress_rules = manager.describe_security_group(security_group_id).ip_permissions_egress

                is_added = False
                for egress_rule in security_group_egress_rules:
                    # Check if egress rule exists in security group
                    if egress_rule.from_port == from_port and egress_rule.to_port == to_port and egress_rule.ip_protocol == ip_protocol:
                        if (ip_ranges and egress_rule.ipv4_ranges and ip_ranges in egress_rule.ipv4_ranges) or (
                                ipv6_ranges and egress_rule.ipv6_ranges and ipv6_ranges in egress_rule.ipv6_ranges):
                            siemplify.LOGGER.info(f"Egress rule found to exist in security group {security_group_id}")
                            is_added = True
                            break

                if is_added:
                    succeed_groups.append(security_group_id)
                else:
                    failed_groups.append(security_group_id)

            if succeed_groups:
                succeed_groups_str = ", ".join(succeed_groups)
                result_value = True
                success_security_group_message = f"Successfully added the specified egress rule to the following " \
                                                 f"security groups: {succeed_groups_str}\n"
                output_message += success_security_group_message
                siemplify.LOGGER.info(success_security_group_message)

            if failed_groups:
                failed_groups_str = ", ".join(failed_groups)
                failed_groups_message = f"Failed to add the specified egress rule to the following security " \
                                        f"groups: {failed_groups_str}\n"
                siemplify.LOGGER.info(failed_groups_message)
                result_value = False

        if invalid_permission_security_group:
            result_value = False
            invalid_permission_security_group_str = ", ".join(invalid_permission_security_group)
            invalid_permission_security_group_message = f"Failed to add the specified egress rule to the following " \
                                                        f"security groups: {invalid_permission_security_group_str}. " \
                                                        f"Reason: Invalid IP Permissions set. For more " \
                                                        f"details please check the logs.\n"

            output_message += invalid_permission_security_group_message

        if not_found_ids:
            result_value = False
            not_found_ids_str = ", ".join(not_found_ids)
            not_found_ids_message = f"Failed to add the specified egress rule to the following security groups:" \
                                    f" {not_found_ids_str}. Reason: Invalid Security Group ID was provided. For more " \
                                    f"details please check the logs."
            output_message += not_found_ids_message

        status = EXECUTION_STATE_COMPLETED

    except Exception as error:
        siemplify.LOGGER.error(f"Error executing action '{AUTHORIZE_SECURITY_GROUP_EGRESS}'. Reason: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Error executing action '{AUTHORIZE_SECURITY_GROUP_EGRESS}'. Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()

