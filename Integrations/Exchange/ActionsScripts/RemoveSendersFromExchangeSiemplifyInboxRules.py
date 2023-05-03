import sys
import json
from ExchangeActions import extract_action_parameter, init_manager
from ExchangeCommon import ExchangeCommon
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED, \
    EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, unix_now, get_email_address, extract_domain
from constants import INTEGRATION_NAME, REMOVE_SENDERS_FROM_EXCHANGE_SIEMPLIFY_INBOX_RULES, \
    PARAMETERS_DEFAULT_DELIMITER, MAILBOX_DEFAULT_LIMIT, ACTIONS, CONDITIONS, CORRESPONDING_RULES, DOMAIN_RULES, \
    SENDER_RULES
from exceptions import NotFoundException, TimeoutException, IncompleteInfoException
from SiemplifyDataModel import EntityTypes


# Constants
ITERATIONS_INTERVAL = 30 * 1000
ITERATION_DURATION_BUFFER = 2 * 60 * 1000
MAX_RETRY = 5  # maximum retry count in case of network error
SUPPORTED_ENTITY_TYPES = [EntityTypes.USER]


def update_rule(logger, manager, rules, email_addresses, mailboxes):
    """
    Find rule and remove provided email addresses from it
    :param logger: {SiemplifyLogger} SiemplifyLogger object.
    :param manager: {ExchangeManager} ExchangeManager object
    :param rules: {list} The list of rules names
    :param email_addresses: {list} The list of email addresses
    :param mailboxes: {list} The list of mailboxes
    :return: {tuple} successful_rules, failed_mailboxes
    """
    successful_rules = []
    accounts, failed_mailboxes = manager.create_account_objects_from_mailboxes(mailboxes)
    try:
        parent_rules = manager.get_rules_by_names(manager.account.primary_smtp_address, rules)
    except Exception:
        parent_rules = []

    for account in accounts:
        logger.info(f"Processing {account.primary_smtp_address} mailbox")
        try:
            current_rules = manager.get_rules_by_names(account.primary_smtp_address, rules)
        except Exception as e:
            logger.error(f"Failed to get rules from mailbox {account.primary_smtp_address}. Error is: {e}")
            failed_mailboxes.append(account.primary_smtp_address)
            continue

        for rule in rules:
            parent_rule = next((parent_rule for parent_rule in parent_rules if parent_rule.name == rule), None) \
                if parent_rules else None
            current_rule = next((current_rule for current_rule in current_rules if current_rule.name == rule), None) \
                if current_rules else None

            try:
                if rule in DOMAIN_RULES:
                    parent_rule_items = parent_rule.conditions.domains if parent_rule else []
                    domains = [extract_domain(email_address) for email_address in email_addresses]

                    successful_rules.append(manager.remove_items_from_rule(
                        account=account,
                        rule_name=rule,
                        condition=CONDITIONS.get("domain"),
                        action=ACTIONS.get(rule),
                        items=domains,
                        parent_rule_items=parent_rule_items,
                        rule=current_rule
                    ))
                else:
                    parent_rule_items = [address.email_address for address in parent_rule.conditions.addresses] \
                        if parent_rule else []
                    successful_rules.append(manager.remove_items_from_rule(
                        account=account,
                        rule_name=rule,
                        condition=CONDITIONS.get("sender"),
                        action=ACTIONS.get(rule),
                        items=email_addresses,
                        parent_rule_items=parent_rule_items,
                        rule=current_rule,
                    ))

            except Exception as e:
                logger.error(f"Failed to update rule from mailbox {account.primary_smtp_address}.")
                logger.exception(e)
                failed_mailboxes.append(account.primary_smtp_address)

    return successful_rules, list(set(failed_mailboxes))


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = REMOVE_SENDERS_FROM_EXCHANGE_SIEMPLIFY_INBOX_RULES
    mode = "Main" if is_first_run else "QueryState"
    siemplify.LOGGER.info("----------------- {} - Param Init -----------------".format(mode))

    # Action parameters
    email_addresses_string = extract_action_parameter(siemplify=siemplify, param_name="Senders",
                                                      print_value=True)
    rule_name = extract_action_parameter(siemplify=siemplify, param_name="Rule to remove Senders from",
                                         is_mandatory=True, print_value=True)
    all_rules = extract_action_parameter(siemplify=siemplify, param_name="Remove Senders from all available Rules",
                                         input_type=bool, print_value=True)
    add_domains = extract_action_parameter(siemplify=siemplify, param_name="Should remove senders' domains from the "
                                                                           "corresponding Domains List rule as well?",
                                           input_type=bool, print_value=True)
    all_mailboxes = extract_action_parameter(siemplify=siemplify, param_name="Perform action in all mailboxes",
                                             input_type=bool, print_value=True)
    batch_size = extract_action_parameter(siemplify=siemplify,
                                          param_name="How many mailboxes to process in a single batch",
                                          input_type=int, default_value=MAILBOX_DEFAULT_LIMIT, print_value=True)

    email_addresses = [email_address.strip() for email_address in email_addresses_string.split(PARAMETERS_DEFAULT_DELIMITER)
                       if email_address.strip()] if email_addresses_string else []

    rules = SENDER_RULES if all_rules else [rule_name]

    if add_domains:
        corresponding_rules = [CORRESPONDING_RULES[rule] for rule in rules]
        rules.extend(corresponding_rules)

    siemplify.LOGGER.info("----------------- {} - Started -----------------".format(mode))
    output_message = ""

    try:
        # Create new exchange manager instance
        manager = init_manager(siemplify, INTEGRATION_NAME)

        if not email_addresses:
            siemplify.LOGGER.info("No email addresses provided in action parameters. Action will work with User "
                                  "entities")
            email_addresses = [
                entity.identifier for entity in siemplify.target_entities
                if entity.entity_type in SUPPORTED_ENTITY_TYPES and get_email_address(entity)
            ]

            if not email_addresses:
                raise IncompleteInfoException

        # Check if script timeout approaching
        if is_script_timeout(siemplify):
            additional_data = json.loads(siemplify.parameters["additional_data"])
            failed_mailboxes = additional_data.get("failed_mailboxes", [])
            processed_mailboxes = additional_data.get("processed_mailboxes", [])
            not_processed_mailboxes = additional_data.get("not_processed_mailboxes", [])
            output_message = prepare_output_messages(rule_name, email_addresses, failed_mailboxes, processed_mailboxes,
                                                     not_processed_mailboxes, add_domains)
            raise TimeoutException

        if is_first_run:
            not_processed_mailboxes = manager.get_searchable_mailboxes_addresses(all_mailboxes)
            siemplify.LOGGER.info(f"Found {len(not_processed_mailboxes)} searchable mailboxes.")
            successful_rules = []
            processed_mailboxes = []
            failed_mailboxes = []
        else:
            additional_data = json.loads(siemplify.parameters["additional_data"])
            successful_rules = additional_data.get("successful_rules", [])
            failed_mailboxes = additional_data.get("failed_mailboxes", [])
            processed_mailboxes = additional_data.get("processed_mailboxes", [])
            not_processed_mailboxes = additional_data.get("not_processed_mailboxes", [])

        batch = not_processed_mailboxes[:batch_size]
        siemplify.LOGGER.info(f"Processing {len(batch)} mailboxes.")

        batch_successful_rules, batch_failed_mailboxes = update_rule(
            logger=siemplify.LOGGER,
            manager=manager,
            rules=rules,
            email_addresses=email_addresses,
            mailboxes=batch
        )

        siemplify.LOGGER.info(f"Updated {len(batch_successful_rules)} rules from "
                              f"{len(batch) - len(batch_failed_mailboxes)} mailboxes (out of {len(batch)} mailboxes"
                              f" in current batch).")

        processed_mailboxes.extend(batch)
        not_processed_mailboxes = not_processed_mailboxes[batch_size:]
        failed_mailboxes.extend(batch_failed_mailboxes)
        successful_rules.extend(batch_successful_rules)

        if not not_processed_mailboxes:
            # Completed processing all mailboxes
            if not successful_rules:
                raise NotFoundException

            result_value = True
            status = EXECUTION_STATE_COMPLETED
            output_message = prepare_output_messages(rule_name, email_addresses, failed_mailboxes, processed_mailboxes,
                                                     not_processed_mailboxes, add_domains)

        else:
            # There are still mailboxes to process
            additional_data = {
                "successful_rules": successful_rules,
                "failed_mailboxes": failed_mailboxes,
                "not_processed_mailboxes": not_processed_mailboxes,
                "processed_mailboxes": processed_mailboxes
            }
            output_message = f"{len(successful_rules)} rule(s) were updated from {len(processed_mailboxes)} " \
                             f"mailboxes (out of {len(processed_mailboxes) + len(not_processed_mailboxes)}). " \
                             f"Continuing."

            status = EXECUTION_STATE_INPROGRESS
            result_value = json.dumps(additional_data)

    except TimeoutException:
        result_value = False
        status = EXECUTION_STATE_TIMEDOUT
    except NotFoundException:
        result_value = False
        output_message = "No rules were found matching the provided name"
        status = EXECUTION_STATE_COMPLETED
    except IncompleteInfoException:
        result_value = False
        output_message = "No email addresses provided in \"Senders\" parameter and there are no email addresses in " \
                         "user entities, Please check action inputs and try again"
        status = EXECUTION_STATE_FAILED
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {REMOVE_SENDERS_FROM_EXCHANGE_SIEMPLIFY_INBOX_RULES}")
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error performing \"{REMOVE_SENDERS_FROM_EXCHANGE_SIEMPLIFY_INBOX_RULES}\" action : {e}"
        additional_data_json = extract_action_parameter(siemplify=siemplify, param_name="additional_data",
                                                        default_value="{}")
        output_message, result_value, status = ExchangeCommon.prevent_async_action_fail_in_case_of_network_error(
            e,
            additional_data_json,
            MAX_RETRY,
            output_message,
            result_value,
            status
        )

    siemplify.LOGGER.info("----------------- {} - Finished -----------------".format(mode))
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


def is_script_timeout(siemplify):
    """
    Check if script timeout approaching
    :param siemplify: SiemplifyAction object.
    :return: {bool} True - if timeout approaching, False - otherwise.
    """
    return unix_now() + ITERATION_DURATION_BUFFER + ITERATIONS_INTERVAL >= siemplify.execution_deadline_unix_time_ms


def prepare_output_messages(rule_name, email_addresses, failed_mailboxes, processed_mailboxes, not_processed_mailboxes,
                            add_domains=None):
    """
    Prepare output messages
    :param rule_name: {str} The rule name
    :param email_addresses: {list} The list of email addresses
    :param failed_mailboxes: {list} The list of failed mailboxes
    :param processed_mailboxes: {list} The list of processed mailboxes
    :param not_processed_mailboxes: {list} The list of not processed mailboxes
    :param add_domains: {bool} Specifies whether domains of the provided email addresses added to corresponding rules
    :return: {str} The output messages
    """
    if add_domains:
        domains = [extract_domain(email_address) for email_address in email_addresses]
        output_message = f"Removed the following inputs from the corresponding rules: " \
                         f"\nSenders: {PARAMETERS_DEFAULT_DELIMITER.join(email_addresses)} " \
                         f"\nDomains: {PARAMETERS_DEFAULT_DELIMITER.join(domains)} " \
                         f"\nRules updated: {rule_name}, {CORRESPONDING_RULES[rule_name]} "
    else:
        output_message = f"Removed the following inputs from the corresponding rules: " \
                         f"\nSenders: {PARAMETERS_DEFAULT_DELIMITER.join(email_addresses)} " \
                         f"\nRules updated: {rule_name} "

    output_message += f"\nSuccessfully updated {len(processed_mailboxes) - len(failed_mailboxes)} mailboxes out of " \
                      f"{len(processed_mailboxes) + len(not_processed_mailboxes)}"

    if failed_mailboxes:
        output_message += f"\nFailed to perform operation on the following mailboxes: " \
                          f"{PARAMETERS_DEFAULT_DELIMITER.join(failed_mailboxes)}"

    return output_message


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)
