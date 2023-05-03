from SiemplifyAction import SiemplifyAction
from RecordedFutureManager import RecordedFutureManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param
from constants import PROVIDER_NAME, PING_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    
    api_url = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="ApiUrl")
    api_key = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="ApiKey")
    verify_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)
    
    recorded_future_manager = RecordedFutureManager(api_url, api_key, verify_ssl=verify_ssl)

    output_message = "Connection Established."
    connectivity_result = True
    status = EXECUTION_STATE_COMPLETED
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        recorded_future_manager.test_connectivity()
        siemplify.LOGGER.info("Connection to API established, performing action {}".format(PING_SCRIPT_NAME))

    except Exception as e:
        output_message = "An error occurred when trying to connect to the API: {}".format(e)
        connectivity_result = False
        siemplify.LOGGER.error("Connection to API failed, performing action {}".format(PING_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.end(output_message, connectivity_result, status)


if __name__ == '__main__':
    main()
