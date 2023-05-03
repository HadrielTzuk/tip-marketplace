from SiemplifyUtils import output_handler
# -*- coding: utf-8 -*-
# ==============================================================================
# title           :CaSoapManager.py
# description     :This Module contain all CA Desk operations functionality using Soap API
# author          :zdemoniac@gmail.com
# date            :1-9-18
# python_version  :2.7
# libraries       :time, xml, zeep
# requirements    :pip install zeep, ticketFields names in CA
# product_version :
# ==============================================================================

# =====================================
#              IMPORTS                #'
# =====================================
from CaSoapManager import CaSoapManager
from SiemplifyJob import SiemplifyJob

import urllib3
import requests
import datetime
import hashlib
import arrow


# =====================================
#             CONSTANTS               #
# =====================================
# Configurations.
DEFAULT_DAYS_BACKWARDS = 0

CA_RULE_NAME = 'CA Desk Manager Ticket.'
OPEN_CASE_STATUS_ENUM = 1
ID_PREFIX_IN_SUMMERY = 'SIEMPLIFY_CASE_ID:'

# Prefixes.
CA_PREFIX = 'CA: History Sync Job CA <-> Siemplify'
SIEMPLIFY_PREFIX = 'SIEMPLIFY:'


# =====================================
#              CLASSES                #
# =====================================
@output_handler
def main():
    try:
        siemplify = SiemplifyJob()

        siemplify.script_name = siemplify.parameters['Script Name']

        siemplify.LOGGER.info('--------------- JOB ITERATION STARTED ---------------')

        # Parameters.
        api_root = siemplify.parameters['API Root']
        username = siemplify.parameters['Username']
        password = siemplify.parameters['Password']
        summery_field = siemplify.parameters.get('Summery Field', 'summary')
        ticket_type_field = siemplify.parameters.get('Ticket Type Field', 'type.sym')
        analyst_name_field = siemplify.parameters.get('Analyst Type Field', 'analyst.combo_name')
        time_stamp_field = siemplify.parameters.get('Time Stamp Field', 'time_stamp')
        ticket_fields_str = siemplify.parameters['Ticket Fields']
        time_zone_string = siemplify.parameters['Timezone String']

        # Turn str lists params to lists object.
        ticket_fields = ticket_fields_str.split(',') if ticket_fields_str else []

        # Configurations.
        ca_manager = CaSoapManager(api_root, username, password)

        # Get last Successful execution time.
        last_success_time = siemplify.fetch_timestamp(datetime_format=False)
        siemplify.LOGGER.info('Got last successful run: {0}'.format(unicode(last_success_time).encode('utf-8')))

        # ----------------- Sync Tickets Comment to Siemplify -----------------
        siemplify.LOGGER.info('########## Sync Tickets Comment to Siemplify ##########')

        # Get tickets that where modified since last success time.
        last_modified_ticket_ids = ca_manager.get_incident_ids_by_filter(
            last_modification_unixtime_milliseconds=last_success_time)
        siemplify.LOGGER.info('Found {0} modified tickets with ids: {1} since {2}'.format(
            unicode(len(last_modified_ticket_ids)).encode('utf-8'),
            unicode(last_modified_ticket_ids).encode('utf-8'),
            unicode(last_success_time).encode('utf-8')))

        for ticket_id in last_modified_ticket_ids:
            siemplify.LOGGER.info('Run on CA incident with id: {0}'.format(unicode(ticket_id).encode('utf-8')))
            # Get Last comments for ticket.
            ticket_comments = ca_manager.get_incident_comments_since_time(ticket_id, last_success_time)
            siemplify.LOGGER.info('Found {0} comment for ticket with id: {1}'.format(unicode(len(ticket_comments)).encode('utf-8'),
                                                                                     unicode(ticket_id).encode('utf-8')))
            # Get Cases id for ticket.
            siemplify.LOGGER.info('Get case IDs for ticket_id: {0}'.format(unicode(ticket_id).encode('utf-8')))
            cases_ids_for_ticket = siemplify.get_cases_by_ticket_id(ticket_id)
            siemplify.LOGGER.info('Got {0} case related to ticket id {1}, the cases IDs are: {2}'.format(
                len(cases_ids_for_ticket),
                unicode(ticket_id).encode('utf-8'),
                unicode(cases_ids_for_ticket).encode('utf-8')))

            # Add comments to cases.
            for case_id in cases_ids_for_ticket:
                siemplify.LOGGER.info('Add comments to case with id: {0}'.format(unicode(case_id).encode('utf-8')))

                # Fetch case comments.
                case_comments_objs_list = siemplify.get_case_comments(str(case_id))
                case_comments_list = [case_comment['comment'] for case_comment
                                        in case_comments_objs_list]

                # fetch alert id for case.
                case_obj = siemplify._get_case_by_id(str(case_id))
                if case_obj:
                    alert_ids = [cyber_alert['external_id'] for cyber_alert in case_obj['cyber_alerts']]
                else:
                    alert_ids = []

                # Sort comments by time.
                ticket_comments = sorted(ticket_comments, key=lambda item: item.get(time_stamp_field, 0))

                for comment in ticket_comments:

                    # Validate that the comment is not from sieplify.
                    # Compare with Siemplify prefix without the column because of the split.
                    siemplify.LOGGER.info('Check if prefix in comment. comment keys:{0}'.format(comment.keys()))
                    if SIEMPLIFY_PREFIX not in comment.get('description', ''):
                        siemplify.LOGGER.info('No prefix found.')
                        # Add prefix to comment.
                        description = comment.get('description', 'No Comment description')
                        if 'description' in comment:
                            del (comment['description'])

                        analyst = comment.get(analyst_name_field, None)
                        ticket_type = comment.get(ticket_type_field, None)
                        ticket_time_stamp = comment.get(time_stamp_field, None)

                        # Convert Unix time to UTC datetime.

                        ticket_time_datetime = arrow.get(
                            float(ticket_time_stamp)).to(time_zone_string) if ticket_time_stamp else None
                        siemplify.LOGGER.info('Building Comment.')
                        case_comment = u"{0} \nTicket ID:{1} \nComment: {2} \nAnalyst: {3} \nTicket Type: {4} \nTime: {5}".format(
                            CA_PREFIX, ticket_id, description, analyst, ticket_type, ticket_time_datetime)
                        # Add comment to case.
                        try:
                            # Validate alert in case.
                            if ticket_id in alert_ids:
                                if case_comment not in case_comments_list:
                                    siemplify.add_comment(case_id=case_id, comment=case_comment, alert_identifier=None)
                                    siemplify.LOGGER.info("Comment Added")
                                else:
                                    siemplify.LOGGER.info("Comment already exists in case.")
                            else:
                                siemplify.LOGGER.info("Alert is not contained in case, comment was not added.")
                        except Exception as err:
                            siemplify.LOGGER.error('Error adding comment to case {0}, ERROR: {1}'.format(case_id,
                                                                                                         err.message))

        # ----------------- Sync Tickets Created From Workflow to Siemplify Cases -----------------
        siemplify.LOGGER.info('########## Sync Tickets Created From Workflow to Siemplify Cases ##########')

        # Extract ticket ids from modified tickets that where opened from workflow.
        for ticket_id in last_modified_ticket_ids:
            siemplify.LOGGER.info('Run on ticket id {0}'.format(ticket_id))
            # Bring the ticket.
            ticket_data = ca_manager.get_incident_by_id(ticket_id, ticket_fields)
            if ticket_data[summery_field] and ID_PREFIX_IN_SUMMERY in ticket_data[summery_field]:
                siemplify.LOGGER.info('Incident with ID {0} was created workflow.'.format(ticket_id))
                # Extract ticket comments.
                ticket_comments = ca_manager.get_incident_comments_since_time(ticket_id, last_success_time)
                # Extract case id from ticket summery.
                case_id = ticket_data[summery_field].split(':')[1]

                # fetch alert id for case.
                case_obj = siemplify._get_case_by_id(str(case_id))
                if case_obj:
                    alert_ids = [cyber_alert['external_id'] for cyber_alert in case_obj['cyber_alerts']]
                else:
                    alert_ids = []

                # Sort comments by time.
                ticket_comments = sorted(ticket_comments, key=lambda item: item.get(time_stamp_field, 0))

                for comment in ticket_comments:
                    # Validate that the comment is not from sieplify.
                    # Compare with Siemplify prefix without the column because of the split.
                    if SIEMPLIFY_PREFIX not in comment.get('description', ''):
                        # Add prefix to comment.
                        description = comment.get('description', 'No Comment description')
                        if 'description' in comment:
                            del (comment['description'])

                        analyst = comment.get(analyst_name_field, None)
                        ticket_type = comment.get(ticket_type_field, None)
                        ticket_time_stamp = comment.get(time_stamp_field, None)

                        # Convert Unix time to UTC datetime.
                        ticket_time_datetime = arrow.get(
                            float(ticket_time_stamp)).to(time_zone_string) if ticket_time_stamp else None

                        case_comment = u"{0} \nTicket ID: {1} \nComment: {2} \nAnalyst: {3} \nTicket Type: {4} \nTime: {5}".format(
                            CA_PREFIX, ticket_id, description, analyst, ticket_type, ticket_time_datetime)

                        # Add comment to case.
                        try:
                            # Validate alert in case.
                            if ticket_id in alert_ids:
                                siemplify.add_comment(case_id=case_id, comment=case_comment, alert_identifier=None)
                                siemplify.LOGGER.info("Comment Added")
                            else:
                                siemplify.LOGGER.info("Alert is not contained in case, comment was not added.")
                        except Exception as err:
                            siemplify.LOGGER.error('Error adding comment to case {0}, ERROR: {1}'.format(case_id,
                                                                                                         err.message))
            else:
                siemplify.LOGGER.info('Incident with id {0} was not created by workflow.'.format(ticket_id))

        # # ----------------- Sync Siemplify Comments to Tickets -----------------
        # siemplify.LOGGER.info('########## Sync Siemplify Comments to Tickets ##########')
        scope_cases = []  # Cases that are in the relevant time scope.
        # Get all open cases.
        open_cases_ids = siemplify.get_cases_by_filter(statuses=[OPEN_CASE_STATUS_ENUM])

        for case_id in open_cases_ids:
            # Get case data.
            case = siemplify._get_case_by_id(str(case_id))
            for alert in case['cyber_alerts']:
                siemplify.LOGGER.info("Iterate over case {0} alerts".format(unicode(case_id).encode('utf-8')))
                if alert['rule_generator'] == CA_RULE_NAME:
                    case_comments = siemplify.get_case_comments(case['identifier'])
                    siemplify.LOGGER.info("Fetch case {0} comments".format(unicode(case_id).encode('utf-8'),
                                                                           len(case_comments)))
                    ticket_id = alert['external_id']
                    for comment in case_comments:
                        # Covert to datetime
                        comment_time = comment['modification_time_unix_time_in_ms']
                        # Check that the comment is newer than the JOB timestamp
                        if comment_time > last_success_time and CA_PREFIX not in \
                                comment['comment']:
                            siemplify.LOGGER.info("Found Case {0} new comment".format(unicode(case_id).encode('utf-8')))
                            # Add to comment Siemplify prefix in order to identify the comment as a siemplify TN comment
                            comment_text = "{0}{1}".format(SIEMPLIFY_PREFIX, comment['comment'])
                            # Update all Alert's tickets in ConnectWise
                            # Add the comment to CA ticket
                            try:
                                siemplify.LOGGER.info("Add comment to ticket {0}".format(ticket_id))
                                ca_manager.add_comment_to_incident(ref_num=ticket_id, comment=comment_text)
                            except Exception as err:
                                siemplify.LOGGER.error("Failed to add comment to ticket {0}, error: {1}".format(
                                    ticket_id, err.message))

        # Update last successful run time.
        siemplify.save_timestamp(datetime_format=True)
        siemplify.LOGGER.info('--------------- JOB ITERATION FINISHED ---------------')

    except Exception as err:
        siemplify.LOGGER.error('Got exception on main handler.Error: {0}'.format(err.message))
        raise


if __name__ == '__main__':
    main()
