import sys
from datetime import timezone

from TIPCommon import (
    extract_connector_param,
    siemplify_save_timestamp,
    get_last_success_time,
    is_overflowed,
    read_ids,
    write_ids
)
from EnvironmentCommon import GetEnvironmentCommonFactory

from JiraConstants import JIRA_TIME_FORMAT, DEFAULT_TIMEOUT_IN_SECONDS
from JiraManager import JiraManager
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyUtils import output_handler
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime
from utils import load_csv_to_list, is_approaching_timeout

connector_starting_time = unix_now()

# CONSTANTS
DEFAULT_DAYS_BACKWARDS = 10
MAX_TICKETS_PER_CYCLE = 10


@output_handler
def main(is_test_run):
    siemplify = SiemplifyConnectorExecution()
    all_tickets = []
    processed_alerts = []

    if is_test_run:
        siemplify.LOGGER.info('***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******')

    siemplify.LOGGER.info('------------------- Main - Param Init -------------------')

    # Connector configurations
    api_root = extract_connector_param(siemplify, param_name='Api Root', is_mandatory=True, print_value=True)
    username = extract_connector_param(siemplify, param_name='Username', is_mandatory=True, print_value=True)
    api_token = extract_connector_param(siemplify, param_name='Api Token', is_mandatory=True, print_value=False)
    use_jira_as_env = extract_connector_param(siemplify, param_name='Use Jira Project as Environment', is_mandatory=False, input_type=bool,
                                              default_value=True, print_value=True)
    verify_ssl = extract_connector_param(siemplify, param_name='Verify SSL', default_value=False, input_type=bool, is_mandatory=False)
    days_backwards = extract_connector_param(siemplify, param_name='Days Backwards', input_type=int, default_value=DEFAULT_DAYS_BACKWARDS,
                                             is_mandatory=False, print_value=True)
    max_tickets_per_cycle = extract_connector_param(siemplify, param_name='Max Tickets Per Cycle', input_type=int,
                                                    default_value=MAX_TICKETS_PER_CYCLE, is_mandatory=False, print_value=True)
    python_process_timeout = extract_connector_param(siemplify, param_name="PythonProcessTimeout", input_type=int, is_mandatory=True,
                                                     default_value=DEFAULT_TIMEOUT_IN_SECONDS, print_value=True)

    issue_statuses = extract_connector_param(siemplify, param_name='Issue Statuses', is_mandatory=False, print_value=True)
    project_names = extract_connector_param(siemplify, param_name='Project Names', is_mandatory=False, print_value=True)
    assign_users = extract_connector_param(siemplify, param_name='Assignees', is_mandatory=False, print_value=True)
    issue_types = extract_connector_param(siemplify, param_name='Issue Types', is_mandatory=False, print_value=True)
    issue_priorities = extract_connector_param(siemplify, param_name='Issue Priorities', is_mandatory=False, print_value=True)
    issue_components = extract_connector_param(siemplify, param_name='Issue Components', is_mandatory=False, print_value=True)

    environment_field_name = extract_connector_param(siemplify, param_name='Environment Field Name', is_mandatory=False,
                                                     default_value='', print_value=True)
    environment_regex_pattern = extract_connector_param(siemplify, param_name='Environment Regex Pattern', print_value=True,
                                                        is_mandatory=False)

    common_environment = GetEnvironmentCommonFactory().create_environment_manager(
        siemplify, environment_field_name, environment_regex_pattern)

    labels = siemplify.whitelist

    try:
        if max_tickets_per_cycle <= 0:
            raise Exception("\"Max Tickets Per Cycle must be\" must be a positive number.")

        issue_statuses = load_csv_to_list(issue_statuses, 'Issue Statuses') if issue_statuses else None
        project_names = load_csv_to_list(project_names, 'Project Names') if project_names else None
        assign_users = load_csv_to_list(assign_users, 'Assignees') if assign_users else None
        issue_types = load_csv_to_list(issue_types, 'Issue Types') if issue_types else None
        issue_priorities = load_csv_to_list(issue_priorities, 'Issue Priorities') if issue_priorities else None
        issue_components = load_csv_to_list(issue_components, 'Issue Components') if issue_components else None

        jira_manager = JiraManager(api_root, username, api_token, verify_ssl=verify_ssl, logger=siemplify.LOGGER)

        # Read already existing alert ids from ids.json file
        siemplify.LOGGER.info("Loading existing ids from IDS file.")
        existing_ids = read_ids(siemplify)
        siemplify.LOGGER.info(f"Found {len(existing_ids)} existing ids in ids.json")

        last_success_time = get_last_success_time(siemplify=siemplify, offset_with_metric={'days': days_backwards})

        # Convert last_success_time from UTC to JIRA server's timezone,
        # as JIRA doesn't support timezone in the JQL query
        # and searches applied using the server's timezone.
        jira_server_time = jira_manager.get_server_time()
        siemplify.LOGGER.info("JIRA server time: {}".format(jira_server_time.isoformat()))
        last_run = last_success_time.replace(tzinfo=timezone.utc).astimezone(jira_server_time.tzinfo)
        siemplify.LOGGER.info("Adjusted last success time to server time: {}".format(last_run.isoformat()))

        # Get alerts
        siemplify.LOGGER.info("Collecting tickets...")
        tickets = jira_manager.list_issues(project_key_list=project_names,
                                           updated_from=last_run.strftime(JIRA_TIME_FORMAT), assignee_list=assign_users,
                                           issue_type_list=issue_types, priority_list=issue_priorities,
                                           labels_list=labels, components_list=issue_components,
                                           only_keys=False, status_list=issue_statuses, order_by="updated", asc=True,
                                           existing_ids=existing_ids, limit=max_tickets_per_cycle)
        tickets = sorted(tickets, key=lambda ticket: ticket.updated_ms)
        siemplify.LOGGER.info(f"Successfully fetched {len(tickets)} tickets")

        if is_test:
            siemplify.LOGGER.info('This is a TEST run. Only 1 alert will be processed.')
            tickets = tickets[:1]

        for ticket in tickets:
            try:
                if len(processed_alerts) >= max_tickets_per_cycle:
                    # Provide slicing for the alerts amount.
                    siemplify.LOGGER.info(f"{len(processed_alerts)} tickets were processed. Stopping connector")
                    break

                if is_approaching_timeout(python_process_timeout, connector_starting_time):
                    siemplify.LOGGER.info('Timeout is approaching. Connector will gracefully exit')
                    break

                # Update existing alerts
                existing_ids.append(ticket.key)
                all_tickets.append(ticket)

                siemplify.LOGGER.info(f"Processing ticket {ticket.key}")
                # Create alert info
                alert_info = ticket.get_alert_info(ticket,
                                                   common_environment,
                                                   siemplify.LOGGER, use_jira_as_env)

                if is_overflowed(siemplify, alert_info, is_test_run):
                    siemplify.LOGGER.info(
                        '{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping.'
                            .format(alert_name=alert_info.rule_generator,
                                    alert_identifier=alert_info.ticket_id,
                                    environment=alert_info.environment,
                                    product=alert_info.device_product))
                    # If is overflowed we should skip
                    continue

                processed_alerts.append(alert_info)
                siemplify.LOGGER.info(f'Ticket {ticket.key} was created.')

            except Exception as error:
                siemplify.LOGGER.error(f"Failed to process ticket {ticket.key}")
                siemplify.LOGGER.exception(error)
                if is_test:
                    raise

            siemplify.LOGGER.info("Completed processing issues.")

        if not is_test:
            if all_tickets:
                new_timestamp = all_tickets[-1].updated_ms
                siemplify.LOGGER.info(
                    f"Saving timestamp of {convert_unixtime_to_datetime(new_timestamp).isoformat()}. Unix: {new_timestamp}")
                siemplify_save_timestamp(siemplify=siemplify, new_timestamp=new_timestamp)
            siemplify.LOGGER.info("Saving existing ids.")
            write_ids(siemplify, existing_ids)

    except Exception as error:
        siemplify.LOGGER.error(f'Got exception on main handler. Error: {error}')
        siemplify.LOGGER.exception(error)
        if is_test:
            raise

    siemplify.LOGGER.info(f'Created total of {len(processed_alerts)} cases')
    siemplify.LOGGER.info('------------------- Main - Finished -------------------')
    siemplify.return_package(processed_alerts)


if __name__ == '__main__':
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test)
