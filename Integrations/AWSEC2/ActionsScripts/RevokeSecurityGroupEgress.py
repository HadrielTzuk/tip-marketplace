from TIPCommon import extract_configuration_param, extract_action_param

from AWSEC2Manager import AWSEC2Manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, REVOKE_SECURITY_GROUP_EGRESS, ALL_IP_PROTOCOLS, IP_PROTOCOLS_MAPPER
from datamodels import SecurityGroupIpPermission
from exceptions import AWSEC2InvalidSecurityGroupException, AWSEC2UnknownIpPermissions, AWSEC2ValidationException, \
    AWSEC2InvalidParameterValueException
from utils import load_csv_to_list


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, REVOKE_SECURITY_GROUP_EGRESS)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # Integration configuration
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
    # Action configuration
    security_group_ids = extract_action_param(siemplify, param_name="Security Group IDs", is_mandatory=True, print_value=True)
    ip_protocol = extract_action_param(siemplify, param_name="IP Protocol", is_mandatory=False, default_value=ALL_IP_PROTOCOLS,
                                       print_value=True)
    ipv4_ranges_cidr = extract_action_param(siemplify, param_name="IP Ranges - CidrIP", is_mandatory=False, print_value=True)
    ipv6_ranges_cidr = extract_action_param(siemplify, param_name="IPv6 Ranges - CidrIP", is_mandatory=False, print_value=True)

    result_value = False
    status = EXECUTION_STATE_COMPLETED
    output_message = ""

    successful_revokes = []
    submitted_security_group_ids = []
    invalid_security_groups = []
    invalid_revokes = []
    failed_revokes = []

    try:
        from_port = extract_action_param(siemplify, param_name="From Port", input_type=int, is_mandatory=False, print_value=True)
        to_port = extract_action_param(siemplify, param_name="To Port", input_type=int, is_mandatory=False, print_value=True)

        security_group_ids = load_csv_to_list(security_group_ids, "Security Group IDs", ",")

        if ip_protocol == ALL_IP_PROTOCOLS:
            to_port = from_port = None
            ip_protocol = IP_PROTOCOLS_MAPPER.get(ip_protocol, '-1')

        siemplify.LOGGER.info(f'Connecting to {INTEGRATION_DISPLAY_NAME} Service')
        manager = AWSEC2Manager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                aws_default_region=aws_default_region)
        manager.test_connectivity()  # this validates the credentials
        siemplify.LOGGER.info(f"Successfully connected to {INTEGRATION_DISPLAY_NAME} service")

        for security_group_id in security_group_ids:
            try:
                siemplify.LOGGER.info(f"Revoking rule from security group with id {security_group_id}")
                manager.revoke_security_group_egress(
                    security_group_id=security_group_id,
                    ip_protocol=ip_protocol,
                    from_port=from_port,
                    to_port=to_port,
                    ipv4_ranges_cidr=ipv4_ranges_cidr,
                    ipv6_ranges_cidr=ipv6_ranges_cidr
                )
                siemplify.LOGGER.info(f"Successfully submitted rule for revoke")
                submitted_security_group_ids.append(security_group_id)

            except AWSEC2InvalidSecurityGroupException as error:
                siemplify.LOGGER.error(f"Failed to revoke egress rule of security group with id {security_group_id}")
                siemplify.LOGGER.exception(error)
                invalid_security_groups.append(security_group_id)

            except (AWSEC2UnknownIpPermissions, AWSEC2ValidationException, AWSEC2InvalidParameterValueException) as error:
                siemplify.LOGGER.error(f"Failed to revoke egress rule of security group with id {security_group_id}")
                siemplify.LOGGER.exception(error)
                invalid_revokes.append(security_group_id)

            except Exception as error:
                siemplify.LOGGER.exception(error)
                siemplify.LOGGER.error(f"Failed to revoke egress rule for security group with id {security_group_id}")
                failed_revokes.append(security_group_id)

        if submitted_security_group_ids:
            # Check if egress rule was removed from security group
            revoked_security_group_ip_permission = SecurityGroupIpPermission(
                to_port=to_port,
                from_port=from_port,
                ip_protocol=ip_protocol,
                ipv4_ranges=[ipv4_ranges_cidr] if ipv4_ranges_cidr else None,
                ipv6_ranges=[ipv6_ranges_cidr] if ipv6_ranges_cidr else None
            )

            for security_group_id in submitted_security_group_ids:
                security_group_egress_rules = manager.describe_security_group(security_group_id).ip_permissions_egress
                siemplify.LOGGER.info(
                    f"Found {len(security_group_egress_rules)} egress rules for security group with id {security_group_id}")
                rule_revoked = True

                for egress_rule in security_group_egress_rules:
                    # Check if egress rule exists in security group after revoke
                    if egress_rule.contains(revoked_security_group_ip_permission):
                        siemplify.LOGGER.info(f"Egress rule found to exist in security group {security_group_id} after revoke")
                        failed_revokes.append(security_group_id)
                        rule_revoked = False
                        break

                if rule_revoked:
                    siemplify.LOGGER.info(f"Rule wasn't found in security group {security_group_id}")
                    successful_revokes.append(security_group_id)

        if successful_revokes:
            output_message += "Successfully revoked the specified egress rule from the following security groups:   {}. \n\n".format(
                ", ".join(successful_revokes)
            )
            result_value = True

        if invalid_revokes:
            output_message += "Failed to revoke the specified egress rule from the following security groups:   {}. Reason: " \
                              "Invalid IP Permissions set. For more details please check the logs. \n\n".format(
                ", ".join(invalid_revokes))
            result_value = False

        if invalid_security_groups:
            output_message += "Failed to revoke the specified egress rule from the following security groups:   {}. Reason: " \
                              "Invalid security Group ID was provided. For more details please check the logs. \n\n".format(
                ", ".join(invalid_security_groups))
            result_value = False

        if failed_revokes:
            output_message += "Failed to revoke the specified egress rule from the following security groups:   {}".format(
                ", ".join(failed_revokes))
            result_value = False

    except Exception as error:
        siemplify.LOGGER.error(f"Error executing action '{REVOKE_SECURITY_GROUP_EGRESS}'. Reason: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Error executing action '{REVOKE_SECURITY_GROUP_EGRESS}'. Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
