from SiemplifyUtils import output_handler
from ArcsightManager import ArcsightManager
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import CHANGE_CASE_STAGE_SCRIPT_NAME, INTEGRATION_NAME, VALID_STAGES


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CHANGE_CASE_STAGE_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    ca_certificate_file = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                      param_name="CA Certificate File")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)

    case_name = extract_action_param(siemplify, param_name="Case Name", print_value=True, is_mandatory=True)
    stage = extract_action_param(siemplify, param_name="Stage", print_value=True, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = "Successfully updated stage to '{}' for case ‘{}’ in {}." \
        .format(stage.upper(), case_name, INTEGRATION_NAME)
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        if stage.upper() not in VALID_STAGES:
            raise Exception("Invalid value was provided in 'Stage' parameter. Acceptable values: {}"
                            .format(", ".join(VALID_STAGES)))

        arcsight_manager = ArcsightManager(server_ip=api_root, username=username, password=password,
                                           verify_ssl=verify_ssl,
                                           ca_certificate_file=ca_certificate_file)
        arcsight_manager.login()
        arcsight_manager.update_case_stage(case_name, stage)
        arcsight_manager.logout()
    except Exception as e:
        output_message = "Error executing action {}. Reason: {}".format(CHANGE_CASE_STAGE_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
