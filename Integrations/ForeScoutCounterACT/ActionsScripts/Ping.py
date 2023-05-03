from TIPCommon import extract_configuration_param

from ForeScoutCounterACTManager import ForeScoutCounterACTManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, PING_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True, print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True, print_value=False, remove_whitespaces=False)
    ca_certificate_file = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="CA Certificate File",
                                                      is_mandatory=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        ForeScoutCounterACTManager(api_root=api_root, username=username, password=password, ca_certificate_file=ca_certificate_file,
                                   verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)
        result = True
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully connected to the {INTEGRATION_DISPLAY_NAME} server with the provided " \
                         f"connection parameters!"

    except Exception as e:
        output_message = f"Failed to connect to the {INTEGRATION_DISPLAY_NAME} server! Error: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
