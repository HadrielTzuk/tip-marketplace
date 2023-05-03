from SiemplifyAction import SiemplifyAction
from McAfeeMvisionEPOV2Manager import McAfeeMvisionEPOV2Manager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import LIST_DEVICES_SCRIPT_NAME, INTEGRATION_NAME, DEFAULT_LIMIT_DEVICES


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_DEVICES_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    # Configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)

    iam_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='IAM Root',
                                           is_mandatory=True)

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client ID',
                                            is_mandatory=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client Secret',
                                                is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Key',
                                          is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=True, input_type=bool)

    scopes = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Scopes',
                                         is_mandatory=True)

    # Parameters
    max_devices_to_return = extract_action_param(siemplify, param_name='Max Devices to Return', is_mandatory=False,
                                                   input_type=int, default_value=DEFAULT_LIMIT_DEVICES)

    if max_devices_to_return <= 0:
        siemplify.LOGGER.info(
            "Max Devices to Return must be positive. Using default value instead ({}).".format(DEFAULT_LIMIT_DEVICES))
        max_devices_to_return = DEFAULT_LIMIT_DEVICES

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ''
    json_results = []

    try:
        siemplify.LOGGER.info("Connecting to McAfee Mvision ePO V2.")
        manager = McAfeeMvisionEPOV2Manager(api_root, iam_root, client_id, client_secret, api_key, scopes, verify_ssl,
                                            siemplify.LOGGER)
        siemplify.LOGGER.info("Successfully connected to McAfee Mvision ePO V2.")

        siemplify.LOGGER.info("Fetching available devices.")
        devices = manager.get_devices(max_devices_to_return)

        if devices:
            siemplify.LOGGER.info("Found {} devices.".format(len(devices)))
            csv_table = [device.to_table_data() for device in devices]
            json_results = [device.to_json() for device in devices]

            siemplify.result.add_data_table(title="Available Devices", data_table=construct_csv(csv_table))
            output_message += "Successfully listed available devices in McAfee Mvision ePO V2"

        else:
            siemplify.LOGGER.info("No devices were found.")
            output_message += "Action wasn’t able to list devices available in McAfee Mvision ePO V2"
            result_value = False

    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(LIST_DEVICES_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message += "Error executing action List Devices. Reason: {0}".format(e)
        result_value = False

    siemplify.result.add_result_json(json_results)
    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
