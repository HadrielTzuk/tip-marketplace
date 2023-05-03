from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ExchangeActions import init_manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, PING_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED

    try:
        # Create new exchange manager instance
        init_manager(siemplify, INTEGRATION_NAME).test_connectivity()
        output_message = "Successfully connected to the Microsoft Exchange server with the provided connection " \
                         "parameters!"

    except Exception as e:
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = "Failed to connect to the Microsoft Exchange server! Error is {}".format(e)
        siemplify.LOGGER.error("Connection to API failed, performing action {}".format(PING_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Status: {}".format(status))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
