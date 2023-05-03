import sys
import json
from ExchangeActions import extract_action_parameter, init_manager
from ExchangeCommon import ExchangeCommon
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED, \
    EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, unix_now
from constants import INTEGRATION_NAME, DELETE_EXCHANGE_SIEMPLIFY_INBOX_RULES, PARAMETERS_DEFAULT_DELIMITER, \
    MAILBOX_DEFAULT_LIMIT, SENDER_RULES, DOMAIN_RULES, ALL_AVAILABLE_SENDERS_RULES_STRING, \
    ALL_AVAILABLE_DOMAINS_RULES_STRING, ALL_AVAILABLE_RULES_STRING
from exceptions import NotFoundException, TimeoutException, IncompleteInfoException


# Constants
ITERATIONS_INTERVAL = 30 * 1000
ITERATION_DURATION_BUFFER = 2 * 60 * 1000
MAX_RETRY = 5  # maximum retry count in case of network error


def delete_rules(logger, manager, rules, mailboxes):
    """
    Find rules and delete them
    :param logger: {SiemplifyLogger} SiemplifyLogger object.
    :param manager: {ExchangeManager} ExchangeManager object
    :param rules: {list} The list of rule names
    :param mailboxes: {list} The list of mailboxes
    :return: {tuple} successful_rules, failed_mailboxes
    """
    successful_rules = []
    accounts, failed_mailboxes = manager.create_account_objects_from_mailboxes(mailboxes)

    for account in accounts:
        logger.info(f"Processing {account.primary_smtp_address} mailbox")

        try:
            current_rules = manager.get_rules_by_names(account.primary_smtp_address, rules)
        except Exception as e:
            logger.error(f"Failed to get rules from mailbox {account.primary_smtp_address}. Error is: {e}")
            failed_mailboxes.append(account.primary_smtp_address)
            continue

        for rule in rules:
            current_rule = next((current_rule for current_rule in current_rules if current_rule.name == rule), None) \
                if current_rules else None

            if current_rule:
                try:
                    successful_rules.append(manager.delete_rule(
                        account=account,
                        rule_id=current_rule.id,
                    ))

                except Exception as e:
                    logger.error(f"Failed to delete rule from mailbox {account.primary_smtp_address}.")
                    logger.exception(e)
                    failed_mailboxes.append(account.primary_smtp_address)
            else:
                logger.error(f"Couldn't find {rule} in mailbox {account.primary_smtp_address}.")

    return successful_rules, list(set(failed_mailboxes))


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = DELETE_EXCHANGE_SIEMPLIFY_INBOX_RULES
    mode = "Main" if is_first_run else "QueryState"
    siemplify.LOGGER.info("----------------- {} - Param Init -----------------".format(mode))

    # Action parameters
    rule_name = extract_action_parameter(siemplify=siemplify, param_name="Rule Name To Delete", is_mandatory=True,
                                         print_value=True)
    all_mailboxes = extract_action_parameter(siemplify=siemplify, param_name="Perform action in all mailboxes",
                                             input_type=bool, print_value=True)

    output_message = ""
    rules = []

    if rule_name == ALL_AVAILABLE_SENDERS_RULES_STRING:
        rules.extend(SENDER_RULES)
    elif rule_name == ALL_AVAILABLE_DOMAINS_RULES_STRING:
        rules.extend(DOMAIN_RULES)
    elif rule_name == ALL_AVAILABLE_RULES_STRING:
        rules.extend(SENDER_RULES + DOMAIN_RULES)
    else:
        rules.append(rule_name)

    rules = list(set(rules))

    try:
        if not rules:
            raise IncompleteInfoException

        batch_size = extract_action_parameter(siemplify=siemplify,
                                              param_name="How many mailboxes to process in a single batch",
                                              input_type=int, default_value=MAILBOX_DEFAULT_LIMIT, print_value=True)

        siemplify.LOGGER.info("----------------- {} - Started -----------------".format(mode))
        # Create new exchange manager instance
        manager = init_manager(siemplify, INTEGRATION_NAME)

        # Check if script timeout approaching
        if is_script_timeout(siemplify):
            additional_data = json.loads(siemplify.parameters["additional_data"])
            failed_mailboxes = additional_data.get("failed_mailboxes", [])
            processed_mailboxes = additional_data.get("processed_mailboxes", [])
            not_processed_mailboxes = additional_data.get("not_processed_mailboxes", [])
            output_message = prepare_output_messages(rules, failed_mailboxes, processed_mailboxes,
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

        batch_successful_rules, batch_failed_mailboxes = delete_rules(
            logger=siemplify.LOGGER,
            manager=manager,
            rules=rules,
            mailboxes=batch,
        )

        siemplify.LOGGER.info(f"Deleted {len(batch_successful_rules)} rules from "
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
            output_message = prepare_output_messages(rules, failed_mailboxes, processed_mailboxes,
                                                     not_processed_mailboxes)

        else:
            # There are still mailboxes to process
            additional_data = {
                "successful_rules": successful_rules,
                "failed_mailboxes": failed_mailboxes,
                "not_processed_mailboxes": not_processed_mailboxes,
                "processed_mailboxes": processed_mailboxes
            }
            output_message = f"{len(successful_rules)} rule(s) were deleted from {len(processed_mailboxes)} " \
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
        output_message = "No rules provided in action parameters, Please check action parameters and try again"
        status = EXECUTION_STATE_FAILED
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {DELETE_EXCHANGE_SIEMPLIFY_INBOX_RULES}")
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error performing \"{DELETE_EXCHANGE_SIEMPLIFY_INBOX_RULES}\" action : {e}"
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


def prepare_output_messages(rule_names, failed_mailboxes, processed_mailboxes, not_processed_mailboxes):
    """
    Prepare output messages
    :param rule_names: {list} The list of rule names
    :param failed_mailboxes: {list} The list of failed mailboxes
    :param processed_mailboxes: {list} The list of processed mailboxes
    :param not_processed_mailboxes: {list} The list of not processed mailboxes
    :return: {str} The output messages
    """
    output_message = f"Deleted the following rules from the specified Mailboxes: " \
                     f"\nRules deleted: {PARAMETERS_DEFAULT_DELIMITER.join(rule_names)}"

    output_message += f"\nSuccessfully updated {len(processed_mailboxes) - len(failed_mailboxes)} mailboxes out of " \
                      f"{len(processed_mailboxes) + len(not_processed_mailboxes)}"

    if failed_mailboxes:
        output_message += f"\nFailed to perform operation on the following mailboxes: " \
                          f"{PARAMETERS_DEFAULT_DELIMITER.join(failed_mailboxes)}"

    return output_message


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)
