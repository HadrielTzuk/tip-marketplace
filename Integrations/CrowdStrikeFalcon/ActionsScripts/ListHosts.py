from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TIPCommon import construct_csv
from CrowdStrikeManager import CrowdStrikeManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import (
    INTEGRATION_NAME,
    LIST_HOSTS_SCRIPT_NAME,
    API_ROOT_DEFAULT,
    HOSTS_TABLE_NAME,
)

MAX_HOSTS_LIMIT = 50


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_HOSTS_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           default_value=API_ROOT_DEFAULT)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client API ID')
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name='Client API Secret')
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                          input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    limit = extract_action_param(siemplify, param_name='Max Hosts To Return', input_type=int, print_value=True,
                                 default_value=MAX_HOSTS_LIMIT)
    filter_value = extract_action_param(siemplify, param_name='Filter Value', print_value=True)
    filter_logic = extract_action_param(siemplify, param_name='Filter Logic', print_value=True)

    result_value = False
    status = EXECUTION_STATE_COMPLETED
    output_message = 'No hosts were found for the provided criteria.'

    try:
        manager = CrowdStrikeManager(client_id=client_id, client_secret=client_secret, use_ssl=use_ssl,
                                     api_root=api_root)

        devices = manager.get_list_devices_by_filter(value=filter_value, filter_strategy=filter_logic, limit=limit)

        if devices:
            siemplify.result.add_data_table(HOSTS_TABLE_NAME, construct_csv([device.to_csv() for device in devices]))
            output_message = 'Successfully retrieved available hosts based on the provided criteria.'
            siemplify.result.add_result_json([device.to_json() for device in devices])
            result_value = True
    except Exception as e:
        output_message = f"Error executing action '{LIST_HOSTS_SCRIPT_NAME}'. Reason: {e}"
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()