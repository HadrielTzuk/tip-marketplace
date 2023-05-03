from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param
from constants import INTEGRATION_NAME, GET_SYSTEM_VERSION_SCRIPT_NAME, SYSTEM_VERSION_TABLE_NAME
from SentinelOneV2Factory import SentinelOneV2ManagerFactory


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_SYSTEM_VERSION_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        sentinel_one_manager = SentinelOneV2ManagerFactory().get_manager(api_root=api_root, api_token=api_token,
                                                                         verify_ssl=verify_ssl)

        siemplify.LOGGER.info('Fetching system version')
        system_version = sentinel_one_manager.get_system_info()

        if system_version:
            siemplify.result.add_data_table(SYSTEM_VERSION_TABLE_NAME, system_version.to_csv())
            output_message = 'System version Found'
        else:
            output_message = 'System version was not found.'

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(GET_SYSTEM_VERSION_SCRIPT_NAME, e)
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
