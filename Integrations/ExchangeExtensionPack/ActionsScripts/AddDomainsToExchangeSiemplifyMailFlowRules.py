import json
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from constants import PROVIDER_NAME, ADD_DOMAINS_TO_EXCHANGE_SIEMPLIFY_MAIL_FLOW_RULES_SCRIPT_NAME, \
    PARAMETERS_DEFAULT_DELIMITER, ACTIONS, CONDITIONS, ASYNC_ACTION_MAX_RETRIES, COMPLETED_STATUS
from ExchangeExtensionPackExceptions import ExchangeExtensionPackIncompleteInfoException, \
    ExchangeExtensionPackIncompleteParametersException, ExchangeExtensionPackPowershellException, \
    ExchangeExtensionPackGssntlmsspException
from ExchangeExtensionPackManager import ExchangeExtensionPackManager
from UtilsManager import validate_domain
from UtilsManager import prevent_async_action_fail_in_case_of_network_error


def get_rules(manager, rule_name):
    """
    Get already existing rules by rule names
    :param manager: ExchangeExtensionPackManager manager object
    :param rule_name: {str} Rule name
    :return: {tuple} output_message, result_value, status
    """
    existing_rules = manager.get_rules_by_names(rule_name)
    existing_rule = existing_rules[0] if existing_rules else None

    status = EXECUTION_STATE_INPROGRESS
    result_value = {
        "get_rules": COMPLETED_STATUS,
    }

    if existing_rule:
        result_value[existing_rule.name] = existing_rule.items
        output_message = f"Found \"{rule_name}\" rule. Continuing..."
    else:
        output_message = f"\"{rule_name}\" rule was not found, new rule will be created. Continuing..."

    return output_message, json.dumps(result_value), status


def add_items_to_rule(siemplify, manager, rule_name, valid_domains, invalid_domains, existing_domains):
    """
    Add items to rule
    :param siemplify: Siemplify object
    :param manager: ExchangeExtensionPackManager manager object
    :param rule_name: {str} Rule name
    :param valid_domains: {list} List of valid domains
    :param invalid_domains: {list} List of invalid domains
    :param existing_domains: {list} List of existing domains
    :return: {tuple} output_message, result_value, status
    """
    manager.add_items_to_rule(
        rule_name=rule_name,
        condition=CONDITIONS.get("domain"),
        action=ACTIONS.get(rule_name),
        items=valid_domains,
        rule_items=existing_domains
    )

    siemplify.result.add_result_json({
        "success": list(set(valid_domains) - set(existing_domains)),
        "already_available": list(set(existing_domains).intersection(valid_domains)),
        "invalid": invalid_domains
    })

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = prepare_output_messages(rule_name, valid_domains, invalid_domains)

    return output_message, result_value, status


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_DOMAINS_TO_EXCHANGE_SIEMPLIFY_MAIL_FLOW_RULES_SCRIPT_NAME

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
    domains_string = extract_action_param(siemplify, param_name="Domains", print_value=True)
    rule_name = extract_action_param(siemplify, param_name="Rule to add Domains to", is_mandatory=True,
                                     print_value=True)

    domains = [domain.strip() for domain in domains_string.split(PARAMETERS_DEFAULT_DELIMITER)
               if domain.strip()] if domains_string else []

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result_value = False
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
            raise ExchangeExtensionPackIncompleteInfoException("Please specify Exchange Office365 Online Powershell Uri")

        valid_domains = [domain for domain in domains if validate_domain(domain)]
        invalid_domains = list(set(domains) - set(valid_domains))

        if not valid_domains:
            raise ExchangeExtensionPackIncompleteParametersException

        # Create manager instance
        manager = ExchangeExtensionPackManager(server_address=server_address, connection_uri=connection_uri,
                                               domain=domain, username=username, password=password,
                                               is_on_prem=is_on_prem, is_office365=is_office365,
                                               siemplify_logger=siemplify.LOGGER)
        additional_data = json.loads(
            extract_action_param(siemplify=siemplify, param_name="additional_data", default_value="{}")
        )

        if additional_data.get("get_rules") != COMPLETED_STATUS:
            output_message, result_value, status = get_rules(manager, rule_name)
        else:
            output_message, result_value, status = add_items_to_rule(siemplify, manager, rule_name, valid_domains,
                                                                     invalid_domains, additional_data.get(rule_name, []))

    except ExchangeExtensionPackIncompleteInfoException as e:
        output_message = str(e)
    except ExchangeExtensionPackIncompleteParametersException:
        output_message = "No valid domains provided in \"Domains\" parameter. Please check action parameters and " \
                         "try again"
    except ExchangeExtensionPackPowershellException as e:
        output_message = f"Failed to execute action because powershell is not installed on Siemplify server! Please" \
                         f" see the configuration instructions on how to install powershell. Error is {e}"
    except ExchangeExtensionPackGssntlmsspException as e:
        output_message = f"Failed to execute action because gssntlmssp package is not installed on Siemplify server!" \
                         f" Please see the configuration instructions on how to install powershell. Error is {e}"
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action "
                               f"{ADD_DOMAINS_TO_EXCHANGE_SIEMPLIFY_MAIL_FLOW_RULES_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        output_message = f"Error performing \"{ADD_DOMAINS_TO_EXCHANGE_SIEMPLIFY_MAIL_FLOW_RULES_SCRIPT_NAME}\" " \
                         f"action: {e}"

        additional_data_json = extract_action_param(siemplify=siemplify, param_name="additional_data",
                                                    default_value="{}")
        output_message, result_value, status = prevent_async_action_fail_in_case_of_network_error(
            e, additional_data_json, ASYNC_ACTION_MAX_RETRIES, output_message, result_value, status
        )

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


def prepare_output_messages(rule, valid_domains, invalid_domains):
    """
    Prepare output messages
    :param rule: {str} The rule name
    :param valid_domains: {list} The list of valid domains
    :param invalid_domains: {list} The list of invalid domains
    :return: {str} The output messages
    """
    output_message = f"Added the following inputs to the corresponding rules:" \
                     f"\nDomains: {PARAMETERS_DEFAULT_DELIMITER.join(valid_domains)}" \
                     f"\nRules updated: {rule}"

    if invalid_domains:
        output_message += f"\nCould not add the following inputs to the rule: " \
                          f"{PARAMETERS_DEFAULT_DELIMITER.join(invalid_domains)}"

    return output_message


if __name__ == '__main__':
    main()
