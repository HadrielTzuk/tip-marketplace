import json
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from constants import PROVIDER_NAME, LIST_EXCHANGE_SIEMPLIFY_MAIL_FLOW_RULES_SCRIPT_NAME, ALL_AVAILABLE_RULES_STRING, \
    SENDER_RULES, DOMAIN_RULES, PARAMETERS_DEFAULT_DELIMITER, ASYNC_ACTION_MAX_RETRIES
from ExchangeExtensionPackExceptions import ExchangeExtensionPackIncompleteInfoException, \
    ExchangeExtensionPackPowershellException, ExchangeExtensionPackGssntlmsspException, ExchangeExtensionPackNotFound
from ExchangeExtensionPackManager import ExchangeExtensionPackManager
from UtilsManager import prevent_async_action_fail_in_case_of_network_error


def run_action(siemplify):
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    server_address = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Exchange On-Prem "
                                                                                                    "Server Address",
                                                 is_mandatory=False, print_value=True)
    connection_uri = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Exchange Office365"
                                                                                                    " Online Powershell"
                                                                                                    " Uri",
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

    # Action parameters
    rule_name = extract_action_param(siemplify, param_name="Rule Name To List", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result_value = False
    status = EXECUTION_STATE_FAILED

    rules = SENDER_RULES + DOMAIN_RULES if rule_name == ALL_AVAILABLE_RULES_STRING else [rule_name]

    try:
        if not is_on_prem and not is_office365:
            raise ExchangeExtensionPackIncompleteInfoException("Please specify type of mail server to connect to - "
                                                               "Exchange on-prem or Office 365")

        if is_on_prem and is_office365:
            raise ExchangeExtensionPackIncompleteInfoException("Only one mail server type is supported at a time. "
                                                               "Please specify type of mail server to connect to - "
                                                               "Exchange on-prem or Office 365")

        if not connection_uri and is_office365:
            raise ExchangeExtensionPackIncompleteInfoException("Please specify Exchange Office365 Online Powershell Uri")

        # Create manager instance
        manager = ExchangeExtensionPackManager(server_address=server_address, connection_uri=connection_uri,
                                               domain=domain, username=username, password=password,
                                               is_on_prem=is_on_prem, is_office365=is_office365,
                                               siemplify_logger=siemplify.LOGGER)

        results = manager.get_rules_by_names(rules)
        results_name = [result.name for result in results]

        if not results:
            raise ExchangeExtensionPackNotFound

        for result in results:
            siemplify.result.add_data_table(result.name, construct_csv(result.to_table()))

        siemplify.result.add_result_json(json.dumps([result.to_json() for result in results]))
        result_value = True
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully listed the following rules: {PARAMETERS_DEFAULT_DELIMITER.join(results_name)}"

        if len(rules) != len(results_name):
            output_message += f"\nCould not list the following rules: " \
                              f"{PARAMETERS_DEFAULT_DELIMITER.join(list(set(rules) - set(results_name)))}, " \
                              f"since they were not found in Exchange. Please make sure you have chosen the " \
                              f"appropriate rule names and try again"

    except ExchangeExtensionPackNotFound:
        result_value = False
        output_message = "Could not list any of the provided rule names, since they were not found in Exchange. " \
                         "Please make sure you have chosen the appropriate rule names and try again"
        status = EXECUTION_STATE_COMPLETED
    except ExchangeExtensionPackIncompleteInfoException as e:
        output_message = str(e)
    except ExchangeExtensionPackPowershellException as e:
        output_message = f"Failed to execute action because powershell is not installed on Siemplify server! Please" \
                         f" see the configuration instructions on how to install powershell. Error is {e}"
    except ExchangeExtensionPackGssntlmsspException as e:
        output_message = f"Failed to execute action because gssntlmssp package is not installed on Siemplify server!" \
                         f" Please see the configuration instructions on how to install powershell. Error is {e}"
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {LIST_EXCHANGE_SIEMPLIFY_MAIL_FLOW_RULES_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        output_message = f"Error performing \"{LIST_EXCHANGE_SIEMPLIFY_MAIL_FLOW_RULES_SCRIPT_NAME}\" action: {e}"

        additional_data_json = extract_action_param(siemplify=siemplify, param_name="additional_data",
                                                    default_value="{}")
        output_message, result_value, status = prevent_async_action_fail_in_case_of_network_error(
            e, additional_data_json, ASYNC_ACTION_MAX_RETRIES, output_message, result_value, status
        )

    return output_message, result_value, status


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_EXCHANGE_SIEMPLIFY_MAIL_FLOW_RULES_SCRIPT_NAME

    output_message, result_value, status = run_action(siemplify)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
