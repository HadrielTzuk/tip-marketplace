from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from MISPManager import MISPManager
from TIPCommon import extract_configuration_param


INTEGRATION_NAME = "MISP"
SCRIPT_NAME = "Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root")
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key")
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Use SSL",
                                          default_value=False, input_type=bool)
    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="CA Certificate File - parsed into Base64 String")

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        MISPManager(api_root, api_token, use_ssl, ca_certificate)
        siemplify.LOGGER.info("Connecting to MISP instance {}.".format(api_root))

        status = EXECUTION_STATE_COMPLETED
        output_message = "Connected successfully."
        result_value = "true"

    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}. Error: {}".format(SCRIPT_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = "General error performing action {}. Error: {}".format(SCRIPT_NAME, e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()