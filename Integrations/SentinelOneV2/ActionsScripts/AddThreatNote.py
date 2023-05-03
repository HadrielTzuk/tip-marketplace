from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import ADD_THREAT_NOTE_SCRIPT_NAME, INTEGRATION_NAME, PRODUCT_NAME
from SentinelOneV2Factory import SentinelOneV2ManagerFactory


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_THREAT_NOTE_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    threat_id = extract_action_param(siemplify, param_name='Threat ID', is_mandatory=True, print_value=True)
    note = extract_action_param(siemplify, param_name='Note', is_mandatory=True, print_value=True)

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = f'Successfully added note to the threat {threat_id} in {PRODUCT_NAME}.'

    try:
        manager = SentinelOneV2ManagerFactory().get_manager(api_root=api_root, api_token=api_token,
                                                            verify_ssl=verify_ssl, force_check_connectivity=True)
        if not manager.add_notes_to_threat([threat_id], note):
            result_value = False
            output_message = f"Action wasn't able to add a note to the threat {threat_id} in {PRODUCT_NAME}."
    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(ADD_THREAT_NOTE_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
