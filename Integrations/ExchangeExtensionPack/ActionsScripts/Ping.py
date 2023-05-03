from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param
from ExchangeExtensionPackManager import ExchangeExtensionPackManager
from constants import PROVIDER_NAME, PING_SCRIPT_NAME
from ExchangeExtensionPackExceptions import ExchangeExtensionPackPowershellException, \
    ExchangeExtensionPackGssntlmsspException, ExchangeExtensionPackIncompleteInfoException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    server_address = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Exchange On-Prem "
                                                                                                    "Server Address",
                                                 is_mandatory=False, print_value=True)
    connection_uri = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Exchange Office365"
                                                                                                    " Compliance Uri",
                                                 is_mandatory=False, print_value=True)
    domain = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Domain", print_value=True)
    username = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="User name",
                                           is_mandatory=False, print_value=True)
    password = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Password",
                                           is_mandatory=False)
    is_on_prem = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Is Exchange On-Prem?",
                                             input_type=bool, print_value=True)
    is_office365 = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME,
                                               param_name="Is Office365 (Exchange Online)?", input_type=bool,
                                               print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result = False
    status = EXECUTION_STATE_FAILED

    try:
        if not is_on_prem and not is_office365:
            raise ExchangeExtensionPackIncompleteInfoException("Please specify type of mail server to connect to - "
                                                               "Exchange on-prem or Office 365")

        if is_on_prem and is_office365:
            raise ExchangeExtensionPackIncompleteInfoException("Only one mail server type is supported at a time. "
                                                               "Please specify type of mail server to connect to - "
                                                               "Exchange on-prem or Office 365")

        if not connection_uri and is_office365:
            raise ExchangeExtensionPackIncompleteInfoException("Please specify Exchange Office365 Compliance Uri")

        manager = ExchangeExtensionPackManager(server_address=server_address, connection_uri=connection_uri,
                                               domain=domain, username=username, password=password,
                                               is_on_prem=is_on_prem, is_office365=is_office365,
                                               siemplify_logger=siemplify.LOGGER)
        manager.test_connectivity()
        result = True
        status = EXECUTION_STATE_COMPLETED
        output_message = "Successfully connected to the Exchange or O365 server with the provided connection " \
                         "parameters!"

    except ExchangeExtensionPackIncompleteInfoException as e:
        output_message = str(e)
    except ExchangeExtensionPackPowershellException as e:
        output_message = f"Failed to execute action because powershell is not installed on Siemplify server! Please" \
                         f" see the configuration instructions on how to install powershell. Error is {e}"
    except ExchangeExtensionPackGssntlmsspException as e:
        output_message = f"Failed to execute action because gssntlmssp package is not installed on Siemplify server!" \
                         f" Please see the configuration instructions on how to install powershell. Error is {e}"
    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(PING_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        output_message = f"Failed to execute action! Error is {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()

