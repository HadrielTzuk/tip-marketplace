from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import (
    extract_configuration_param,
    extract_action_param,
    convert_comma_separated_to_list
)
from QualysVMManager import QualysVMManager
from constants import INTEGRATION_NAME, LAUNCH_COMPLIANCE_REPORT_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LAUNCH_COMPLIANCE_REPORT_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True, print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    # Action parameters
    report_title = extract_action_param(siemplify, param_name="Report Title", is_mandatory=True, print_value=True)
    template_name = extract_action_param(siemplify, param_name="Report Type", is_mandatory=True, print_value=True)
    output_format = extract_action_param(siemplify, param_name="Output Format", is_mandatory=True, print_value=True)
    ips = extract_action_param(siemplify, param_name="IPs/Ranges", print_value=True)
    asset_groups = extract_action_param(siemplify, param_name="Asset Groups", default_value="", print_value=True)
    report_refs = extract_action_param(siemplify, param_name="Scan Reference", print_value=True)

    asset_group_names = convert_comma_separated_to_list(asset_groups)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    asset_group_ids = []

    try:
        qualys_manager = QualysVMManager(api_root, username, password, verify_ssl)

        for asset_group_name in asset_group_names:
            matching_asset_groups = qualys_manager.list_asset_groups(title=asset_group_name)

            if matching_asset_groups:
                asset_group_ids.append(matching_asset_groups[0].get("ID"))

        template_id = qualys_manager.get_template_id_by_name(template_name)

        report_id = qualys_manager.launch_compliance_report(
            report_title=report_title,
            template_id=template_id,
            output_format=output_format,
            ips=ips,
            asset_group_ids=asset_group_ids,
            report_refs=report_refs,
        )

        output_message = f"Compliance report was initialized. Report ID: {report_id}."

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {LAUNCH_COMPLIANCE_REPORT_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        report_id = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{LAUNCH_COMPLIANCE_REPORT_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(report_id))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, report_id, status)


if __name__ == "__main__":
    main()
