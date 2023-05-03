from SiemplifyUtils import output_handler
from SplunkManager import SplunkManager
from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import convert_unixtime_to_datetime, utc_now, convert_datetime_to_unix_time
from TIPCommon import extract_action_param
from constants import (OPEN_CASE_STATUS_ENUM, SIEMPLIFY_COMMENT_PREFIX, SPLUNK_COMMENT_PREFIX,
                       SYNC_COMMENTS_SCRIPT_NAME, DEFAULT_DEVICE_PRODUCT)
import urllib3
import requests


@output_handler
def main():
    siemplify = SiemplifyJob()

    try:
        siemplify.script_name = SYNC_COMMENTS_SCRIPT_NAME

        siemplify.LOGGER.info('--------------- JOB STARTED ---------------')

        # Configurations.
        server_address = extract_action_param(
            siemplify=siemplify,
            param_name='Server Address',
            is_mandatory=True,
            print_value=True
        )

        username = extract_action_param(
            siemplify=siemplify,
            param_name='Username',
            print_value=False
        )

        password = extract_action_param(
            siemplify=siemplify,
            param_name='Password',
            print_value=False
        )

        api_token = extract_action_param(
            siemplify=siemplify,
            param_name='API Token',
            print_value=False
        )
        verify_ssl = extract_action_param(
            siemplify=siemplify,
            input_type=bool,
            param_name='Verify SSL',
        )
        ca_certificate = extract_action_param(
            siemplify=siemplify,
            param_name='CA Certificate File',
            print_value=False
        )

        manager = SplunkManager(server_address=server_address, verify_ssl=verify_ssl, username=username,
                                password=password, api_token=api_token, ca_certificate=ca_certificate,
                                siemplify_logger=siemplify.LOGGER)

        # Get last Successful execution time.
        last_successful_execution_time = siemplify.fetch_timestamp(datetime_format=True)

        # Save current time at timestamp to make sure all alerts are taken.
        new_timestamp = utc_now()

        # Get open cases that created by the connector
        cases_ids = siemplify.get_cases_by_filter(case_names=[DEFAULT_DEVICE_PRODUCT], statuses=[OPEN_CASE_STATUS_ENUM])
        if cases_ids:
            siemplify.LOGGER.info("Found {0} open cases".format(len(cases_ids)))
        siemplify.LOGGER.info(cases_ids)
        all_cases = []
        for case_id in cases_ids:
            case = siemplify._get_case_by_id(str(case_id))
            all_cases.append(case)

        # Sync Events Comments to Splunk ES
        siemplify.LOGGER.info('--- Start synchronize Events Comments from Siemplify to Splunk ES ---')

        for case in all_cases:
            siemplify.LOGGER.info('Run on case with id: {0}'.format(case.get('identifier')))
            case_comments = siemplify.get_case_comments(case.get('identifier'))
            siemplify.LOGGER.info("Found {0} comments for case with id: {1} ".format(len(case_comments), case.get('identifier')))

            for comment in case_comments:
                # Covert to datetime
                comment_time = convert_unixtime_to_datetime((comment.get('modification_time_unix_time_in_ms', 0)))

                # Check that the comment is newer than the JOB timestamp and comment didn't come from Splunk ES
                if comment_time > last_successful_execution_time and not comment.get('comment')\
                        .startswith(SPLUNK_COMMENT_PREFIX):
                    siemplify.LOGGER.info("Found new comment at Case {0}".format(case.get('identifier')))

                    # Add to comment Siemplify prefix in order to identify the comment as a siemplify comment
                    comment_text = "{0}{1}".format(SIEMPLIFY_COMMENT_PREFIX, comment.get('comment'))

                    # Update all Alert's tickets in Splunk
                    for alert in case.get('cyber_alerts', []):
                        if alert.get('reporting_product') == DEFAULT_DEVICE_PRODUCT:
                            ticket_number = alert.get('additional_properties', {}).get('TicketId')
                        else:
                            ticket_number = alert.get('additional_data')

                        if ticket_number:
                            # Add the comment to Splunk ticket
                            try:
                                manager.add_comment_to_event(ticket_number, comment_text)
                                siemplify.LOGGER.info("Add comment to ticket {0}".format(ticket_number))
                            except Exception as err:
                                siemplify.LOGGER.error(
                                    "Failed to add comment to ticket {0}, error: {1}".format(ticket_number, err.message))
                                siemplify.LOGGER.exception(err)
                        else:
                            siemplify.LOGGER.info("Cannot find issue key. Comments from case {0} not added to issue"
                                                  .format(case.get('identifier')))

        siemplify.LOGGER.info(" --- Finish synchronize comments from cases to Splunk tickets --- ")

        # Sync Events Comment to Siemplify
        siemplify.LOGGER.info('--- Start synchronize Events Comments from Splunk to Siemplify ---')

        for case in all_cases:
            for alert in case.get('cyber_alerts', []):
                if alert.get('reporting_product') == DEFAULT_DEVICE_PRODUCT:
                    ticket_number = alert.get('additional_properties', {}).get('TicketId')
                else:
                    ticket_number = alert.get('additional_data')

                if ticket_number:
                    try:
                        tickets = manager.get_events_by_filter(event_ids=[ticket_number])
                        if tickets:
                            ticket = tickets[0]
                            if ticket.comments:
                                ticket_matching_case_id = case.get('identifier')
                                case_comments = [comment.get('comment') for comment in
                                             siemplify.get_case_comments(ticket_matching_case_id)]
                                siemplify.LOGGER.info(
                                    'Found {0} comment for event: {1}'.format(len(ticket.comments), ticket_number))

                                # Get all comments that didn't come from Siemplify
                                comments_to_add = [comment for comment in ticket.comments
                                                   if not comment.startswith(SIEMPLIFY_COMMENT_PREFIX)]
                                comments_to_add = [comment for comment in comments_to_add if
                                                   "{0}{1}".format(SPLUNK_COMMENT_PREFIX, comment) not in case_comments]

                                # Add comments to cases.
                                if comments_to_add:
                                    siemplify.LOGGER.info(
                                        'Add comments to case with id: {0}'.format(ticket_matching_case_id))
                                    for comment in comments_to_add:
                                        comment_with_prefix = "{0}{1}".format(SPLUNK_COMMENT_PREFIX, comment)
                                        siemplify.add_comment(comment_with_prefix, ticket_matching_case_id, None)
                                    siemplify.LOGGER.info("Comments were added successfully")
                                else:
                                    siemplify.LOGGER.info("No new comments in event -{0}".format(ticket_number))

                            else:
                                siemplify.LOGGER.info("No new comments in event -{0}".format(ticket_number))

                    except Exception as err:
                        siemplify.LOGGER.error('Failed to get details for event {}.'.format(ticket_number))
                        siemplify.LOGGER.exception(err)
                else:
                    siemplify.LOGGER.info("Cannot find issue key. Comments from case {0} not added to issue".format(
                        case.get('identifier')))

        siemplify.LOGGER.info(" --- Finish synchronize comments from Splunk notable events to cases --- ")
        # Update last successful run time with new_timestamp.
        siemplify.save_timestamp(new_timestamp=new_timestamp)
        siemplify.LOGGER.info('--------------- JOB FINISHED ---------------')

    except Exception as err:
        siemplify.LOGGER.exception('Got exception on main handler.Error: {0}'.format(err))
        raise


if __name__ == '__main__':
    main()
