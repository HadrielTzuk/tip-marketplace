from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param
from CiscoOrbitalManager import CiscoOrbitalManager
from constants import PROVIDER_NAME, PING_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    client_id = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Client ID",
                                            is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Client Secret",
                                                is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = CiscoOrbitalManager(client_id=client_id, client_secret=client_secret, verify_ssl=verify_ssl,
                                      siemplify_logger=siemplify.LOGGER)
        manager.test_connectivity()
        result = True
        status = EXECUTION_STATE_COMPLETED
        output_message = "Successfully connected to the Cisco Orbital server with the provided connection parameters!"
    except Exception as e:
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = "Failed to connect to the Cisco Orbital server! Error is {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
