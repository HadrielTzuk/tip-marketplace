import sys
import json
from ExchangeActions import extract_action_parameter, init_manager
from ExchangeCommon import ExchangeCommon
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED, \
    EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, unix_now
from constants import INTEGRATION_NAME, ADD_DOMAINS_TO_EXCHANGE_SIEMPLIFY_INBOX_RULES, PARAMETERS_DEFAULT_DELIMITER, \
    MAILBOX_DEFAULT_LIMIT, ACTIONS, CONDITIONS
from exceptions import NotFoundException, TimeoutException, IncompleteInfoException


# Constants
ITERATIONS_INTERVAL = 30 * 1000
ITERATION_DURATION_BUFFER = 2 * 60 * 1000
MAX_RETRY = 5  # maximum retry count in case of network error


def update_rule(logger, manager, rule_name, domains, mailboxes):
    """
    Find rule and update it with provided domains, if rule not found create new rule
    :param logger: {SiemplifyLogger} SiemplifyLogger object.
    :param manager: {ExchangeManager} ExchangeManager object
    :param rule_name: {str} The rule name
    :param domains: {list} The list of domains
    :param mailboxes: {list} The list of mailboxes
    :return: {tuple} successful_rules, failed_mailboxes
    """
    successful_rules = []
    accounts, failed_mailboxes = manager.create_account_objects_from_mailboxes(mailboxes)

    try:
        parent_rules = manager.get_rules_by_names(manager.account.primary_smtp_address, [rule_name])
        parent_rule_items = parent_rules[0].conditions.domains if parent_rules else []
    except Exception:
        parent_rule_items = []

    for account in accounts:
        logger.info(f"Processing {account.primary_smtp_address} mailbox")
        try:
            current_rules = manager.get_rules_by_names(account.primary_smtp_address, [rule_name])
        except Exception as e:
            logger.error(f"Failed to get rules from mailbox {account.primary_smtp_address}. Error is: {e}")
            failed_mailboxes.append(account.primary_smtp_address)
            continue

        try:
            successful_rules.append(manager.add_items_to_rule(
                account=account,
                rule_name=rule_name,
                condition=CONDITIONS.get("domain"),
                action=ACTIONS.get(rule_name),
                items=domains,
                parent_rule_items=parent_rule_items,
                rule=current_rules[0] if current_rules else None,
            ))

        except Exception as e:
            logger.error(f"Failed to update rule from mailbox {account.primary_smtp_address}.")
            logger.exception(e)
            failed_mailboxes.append(account.primary_smtp_address)

    return successful_rules, list(set(failed_mailboxes))


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_DOMAINS_TO_EXCHANGE_SIEMPLIFY_INBOX_RULES
    mode = "Main" if is_first_run else "QueryState"
    siemplify.LOGGER.info("----------------- {} - Param Init -----------------".format(mode))

    # Action parameters
    domains_string = extract_action_parameter(siemplify=siemplify, param_name="Domains", print_value=True)
    rule_name = extract_action_parameter(siemplify=siemplify, param_name="Rule to add Domains to", is_mandatory=True,
                                         print_value=True)
    all_mailboxes = extract_action_parameter(siemplify=siemplify, param_name="Perform action in all mailboxes",
                                             input_type=bool, print_value=True)
    batch_size = extract_action_parameter(siemplify=siemplify,
                                          param_name="How many mailboxes to process in a single batch",
                                          input_type=int, default_value=MAILBOX_DEFAULT_LIMIT, print_value=True)

    domains = [domain.strip() for domain in domains_string.split(PARAMETERS_DEFAULT_DELIMITER) if domain.strip()] \
        if domains_string else []

    siemplify.LOGGER.info("----------------- {} - Started -----------------".format(mode))
    output_message = ""

    try:
        # Create new exchange manager instance
        manager = init_manager(siemplify, INTEGRATION_NAME)

        if not domains:
            raise IncompleteInfoException

        # Check if script timeout approaching
        if is_script_timeout(siemplify):
            additional_data = json.loads(siemplify.parameters["additional_data"])
            failed_mailboxes = additional_data.get("failed_mailboxes", [])
            processed_mailboxes = additional_data.get("processed_mailboxes", [])
            not_processed_mailboxes = additional_data.get("not_processed_mailboxes", [])
            output_message = prepare_output_messages(rule_name, domains, failed_mailboxes, processed_mailboxes,
                                                     not_processed_mailboxes)
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
            rule_name=rule_name,
            domains=domains,
            mailboxes=batch,
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
            output_message = prepare_output_messages(rule_name, domains, failed_mailboxes, processed_mailboxes,
                                                     not_processed_mailboxes)

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
        output_message = "No domains provided in \"Domains\" parameter, Please check action parameters and try again"
        status = EXECUTION_STATE_FAILED
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {ADD_DOMAINS_TO_EXCHANGE_SIEMPLIFY_INBOX_RULES}")
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error performing \"{ADD_DOMAINS_TO_EXCHANGE_SIEMPLIFY_INBOX_RULES}\" action : {e}"
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


def prepare_output_messages(rule_name, domains, failed_mailboxes, processed_mailboxes, not_processed_mailboxes):
    """
    Prepare output messages
    :param rule_name: {str} The rule name
    :param domains: {list} The list of domains
    :param failed_mailboxes: {list} The list of failed mailboxes
    :param processed_mailboxes: {list} The list of processed mailboxes
    :param not_processed_mailboxes: {list} The list of not processed mailboxes
    :return: {str} The output messages
    """
    output_message = f"Added the following Domains to the corresponding rules: " \
                     f"\nDomains: {PARAMETERS_DEFAULT_DELIMITER.join(domains)} " \
                     f"\nRules updated: {rule_name}"

    output_message += f"\nSuccessfully updated {len(processed_mailboxes) - len(failed_mailboxes)} mailboxes out of " \
                      f"{len(processed_mailboxes) + len(not_processed_mailboxes)}"

    if failed_mailboxes:
        output_message += f"\nFailed to perform operation on the following mailboxes: " \
                          f"{PARAMETERS_DEFAULT_DELIMITER.join(failed_mailboxes)}"

    return output_message


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)
