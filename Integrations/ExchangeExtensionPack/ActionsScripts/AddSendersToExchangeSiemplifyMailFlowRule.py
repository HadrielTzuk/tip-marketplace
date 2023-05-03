import json
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, get_email_address, extract_domain
from constants import PROVIDER_NAME, ADD_SENDERS_TO_EXCHANGE_SIEMPLIFY_MAIL_FLOW_RULE_SCRIPT_NAME, \
    PARAMETERS_DEFAULT_DELIMITER, ACTIONS, CONDITIONS, CORRESPONDING_RULES, DOMAIN_RULES, ASYNC_ACTION_MAX_RETRIES, \
    COMPLETED_STATUS
from SiemplifyDataModel import EntityTypes
from ExchangeExtensionPackExceptions import ExchangeExtensionPackIncompleteInfoException, \
    ExchangeExtensionPackIncompleteParametersException, ExchangeExtensionPackPowershellException, \
    ExchangeExtensionPackGssntlmsspException
from ExchangeExtensionPackManager import ExchangeExtensionPackManager
from UtilsManager import validate_email_address
from UtilsManager import prevent_async_action_fail_in_case_of_network_error


# Constants
SUPPORTED_ENTITY_TYPES = [EntityTypes.USER]


def get_rules(manager, rules):
    """
    Get already existing rules by rule names
    :param manager: ExchangeExtensionPackManager manager object
    :param rules: {list} List of rule names
    :return: {tuple} output_message, result_value, status
    """
    existing_rules = manager.get_rules_by_names(rules)
    status = EXECUTION_STATE_INPROGRESS
    result_value = {
        "get_rules": COMPLETED_STATUS,
    }

    for existing_rule in existing_rules:
        result_value[existing_rule.name] = existing_rule.items

    if existing_rules:
        output_message = "Found {} rules. Continuing...".format(
            PARAMETERS_DEFAULT_DELIMITER.join([f'"{existing_rule.name}"' for existing_rule in existing_rules])
        )
    else:
        output_message = f"No rules were found matching the provided names, new rules will be created. Continuing..."

    return output_message, json.dumps(result_value), status


def add_items_to_rule(siemplify, manager, rules, valid_items, invalid_items, add_domains, additional_data):
    """
    Add items to rule
    :param siemplify: Siemplify object
    :param manager: ExchangeExtensionPackManager manager object
    :param rules: {list} List of rule names
    :param valid_items: {list} List of valid items
    :param invalid_items: {list} List of invalid items
    :param add_domains: {bool} Specifies whether domains of the provided email addresses added to corresponding rules
    :param additional_data: {dict} Additional data from previous iteration
    :return: {tuple} output_message, result_value, status
    """
    processed_rules = additional_data.get("processed_rules", [])
    not_processed_rules = list(set(rules) - set(processed_rules))
    rule_name = not_processed_rules[0]
    existing_items = additional_data.get(rule_name, [])

    if rule_name in DOMAIN_RULES:
        domains = list(set([extract_domain(valid_item) for valid_item in valid_items]))

        manager.add_items_to_rule(
            rule_name=rule_name,
            condition=CONDITIONS.get("domain"),
            action=ACTIONS.get(rule_name),
            items=domains,
            rule_items=existing_items
        )
    else:
        manager.add_items_to_rule(
            rule_name=rule_name,
            condition=CONDITIONS.get("sender"),
            action=ACTIONS.get(rule_name),
            items=valid_items,
            rule_items=existing_items,
        )

    processed_rules.append(rule_name)

    if len(rules) == len(processed_rules):
        siemplify.result.add_result_json({
            "success": list(set(valid_items) - set(existing_items)),
            "already_available": list(set(existing_items).intersection(valid_items)),
            "invalid": invalid_items
        })

        result_value = True
        status = EXECUTION_STATE_COMPLETED
        output_message = prepare_output_messages(rules, valid_items, invalid_items, add_domains)
    else:
        additional_data.update({
            "processed_rules": processed_rules
        })
        result_value = json.dumps(additional_data)
        status = EXECUTION_STATE_INPROGRESS
        output_message = f"Rules updated: {PARAMETERS_DEFAULT_DELIMITER.join(processed_rules)}. Continuing..."

    return output_message, result_value, status


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_SENDERS_TO_EXCHANGE_SIEMPLIFY_MAIL_FLOW_RULE_SCRIPT_NAME

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
    email_addresses_string = extract_action_param(siemplify, param_name="Email Addresses", print_value=True)
    rule_name = extract_action_param(siemplify, param_name="Rule to add senders to", is_mandatory=True,
                                     print_value=True)
    add_domains = extract_action_param(siemplify, param_name="Should add senders' domain to the corresponding Domains "
                                                             "List rule as well?", input_type=bool, print_value=True)

    email_addresses = [email_address.strip() for email_address in
                       email_addresses_string.split(PARAMETERS_DEFAULT_DELIMITER)
                       if email_address.strip()] if email_addresses_string else []

    rules = [rule_name, CORRESPONDING_RULES[rule_name]] if add_domains else [rule_name]

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
            raise ExchangeExtensionPackIncompleteInfoException(
                "Please specify Exchange Office365 Online Powershell Uri")

        # Create manager instance
        manager = ExchangeExtensionPackManager(server_address=server_address, connection_uri=connection_uri,
                                               domain=domain, username=username, password=password,
                                               is_on_prem=is_on_prem, is_office365=is_office365,
                                               siemplify_logger=siemplify.LOGGER)

        if not email_addresses:
            siemplify.LOGGER.info("No email addresses provided in action parameters. Action will work with User "
                                  "entities")
            email_addresses = [
                entity.identifier for entity in siemplify.target_entities
                if entity.entity_type in SUPPORTED_ENTITY_TYPES and validate_email_address(entity.identifier)
            ]

        valid_email_addresses = [email_address for email_address in email_addresses
                                 if validate_email_address(email_address)]
        invalid_email_addresses = list(set(email_addresses) - set(valid_email_addresses))

        if not valid_email_addresses:
            raise ExchangeExtensionPackIncompleteParametersException

        additional_data = json.loads(
            extract_action_param(siemplify=siemplify, param_name="additional_data", default_value="{}")
        )

        if additional_data.get("get_rules") != COMPLETED_STATUS:
            output_message, result_value, status = get_rules(manager, rules)
        else:
            output_message, result_value, status = add_items_to_rule(siemplify, manager, rules, valid_email_addresses,
                                                                     invalid_email_addresses, add_domains,
                                                                     additional_data)

    except ExchangeExtensionPackIncompleteInfoException as e:
        output_message = str(e)
    except ExchangeExtensionPackIncompleteParametersException:
        output_message = "No valid email addresses provided in \"Email Addresses\" parameter, or there are no valid " \
                         "email addresses found in the user entities. Please check action inputs and try again"
    except ExchangeExtensionPackPowershellException as e:
        output_message = f"Failed to execute action because powershell is not installed on Siemplify server! Please" \
                         f" see the configuration instructions on how to install powershell. Error is {e}"
    except ExchangeExtensionPackGssntlmsspException as e:
        output_message = f"Failed to execute action because gssntlmssp package is not installed on Siemplify server!" \
                         f" Please see the configuration instructions on how to install powershell. Error is {e}"
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action "
                               f"{ADD_SENDERS_TO_EXCHANGE_SIEMPLIFY_MAIL_FLOW_RULE_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        output_message = f"Error performing \"{ADD_SENDERS_TO_EXCHANGE_SIEMPLIFY_MAIL_FLOW_RULE_SCRIPT_NAME}\" " \
                         f"action : {e}"
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


def prepare_output_messages(rules, valid_email_addresses, invalid_email_addresses, add_domains=None):
    """
    Prepare output messages
    :param rules: {list} The list of rule names
    :param valid_email_addresses: {list} The list of valid email addresses
    :param invalid_email_addresses: {list} The list of invalid email addresses
    :param add_domains: {bool} Specifies whether domains of the provided email addresses added to corresponding rules
    :return: {str} The output messages
    """
    output_message = f"Added the following inputs to the corresponding rules: " \
                     f"\nEmail Addresses: {PARAMETERS_DEFAULT_DELIMITER.join(valid_email_addresses)}"

    if add_domains:
        domains = list(set([extract_domain(email_address) for email_address in valid_email_addresses]))
        output_message += f"\nDomains: {PARAMETERS_DEFAULT_DELIMITER.join(domains)}"

    output_message += f"\nRules updated: {PARAMETERS_DEFAULT_DELIMITER.join(rules)}"

    if invalid_email_addresses:
        output_message += f"\nCould not add the following inputs to the rule: " \
                          f"{PARAMETERS_DEFAULT_DELIMITER.join(invalid_email_addresses)}"

    return output_message


if __name__ == '__main__':
    main()
