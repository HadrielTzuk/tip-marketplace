from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CrowdStrikeManager import CrowdStrikeManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import (
    INTEGRATION_NAME,
    PRODUCT_NAME,
    CLOSE_DETECTION_SCRIPT_NAME,
    API_ROOT_DEFAULT,
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CLOSE_DETECTION_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           default_value=API_ROOT_DEFAULT)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client API ID')
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name='Client API Secret')
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                          input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    detection_id = extract_action_param(siemplify, param_name='Detection ID', is_mandatory=True)
    hide_detection = extract_action_param(siemplify, param_name="Hide Detection", input_type=bool, print_value=True)

    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = CrowdStrikeManager(client_id=client_id, client_secret=client_secret, use_ssl=use_ssl,
                                     api_root=api_root)

        manager.close_detection(detection_id, show_in_ui=False if hide_detection else True)

        output_message = f'Successfully closed detection with id: {detection_id}.'
    except Exception as e:
        output_message = f"Error executing action '{CLOSE_DETECTION_SCRIPT_NAME}'. Reason: {e}"
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()