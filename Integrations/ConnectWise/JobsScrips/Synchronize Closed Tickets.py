from SiemplifyUtils import output_handler
# ==============================================================================
# title           : Job.ConnectWise.CloseTicketInCW.py
# description     : Job - Closes ticket at ConnectWise for closed cases in Siemplify.
# author          :victor@siemplify.co
# date            :7-1-18
# python_version  :2.7
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import convert_datetime_to_unix_time
from ConnectWiseManager import ConnectWiseManager
import urllib3
import requests


# =====================================
#              CLASSES                #
# =====================================
@output_handler
def main():

    siemplify = SiemplifyJob()

    try:
        # Parameters.
        script_name = siemplify.parameters['Script Name']
        api_root = siemplify.parameters['API Root']
        company_name = siemplify.parameters['Company Name']
        public_api_key = siemplify.parameters['API Public Key']
        private_api_key = siemplify.parameters['API Private Key']

        siemplify.script_name = script_name
        
        siemplify.LOGGER.info("-----Job Started-----")

        connectwise_manager = ConnectWiseManager(api_root, company_name, public_api_key, private_api_key)

        # Get last successful execution time.
        last_execution_time = siemplify.fetch_timestamp(datetime_format=True)
        siemplify.LOGGER.info('Got last successful execution time: {0}'.format(unicode(last_execution_time).encode('utf-8')))

        # Convert timestamp to unixtime.
        time_stamp = convert_datetime_to_unix_time(last_execution_time)

        siemplify.LOGGER.info(' +++ Close Ticket In CW. +++ ')
        #         Close Ticket In CW
        # =====================================

        # Get  all scope alerts.
        closed_cases_alerts = siemplify.get_alerts_ticket_ids_from_cases_closed_since_timestamp(time_stamp, None)

        # Get dismissed alerts ids.
        dismissed_alerts = siemplify.get_ticket_ids_for_alerts_dismissed_since_timestamp(time_stamp)

        # Unite the alerts lists.
        alerts_ids_list = closed_cases_alerts.extend(dismissed_alerts)

        # Unify the united alerts ids list.
        alerts_set = set(alerts_ids_list)
        unique_alerts_ids_list = list(alerts_set)
        siemplify.LOGGER.info('Found {0} dismissed alerts.'.format(len(unique_alerts_ids_list)))

        for alert_ticket_id in unique_alerts_ids_list:
            case_ids_list = siemplify.get_cases_by_ticket_id(alert_ticket_id)
            siemplify.LOGGER.info('Found the following cases: {0} for alert with ticket id: {1}'.format(
                unicode(case_ids_list).encode('utf-8'),
                unicode(alert_ticket_id).encode('utf-8')))
            # There has to be one case ID except the SIEM is QRadar.
            for scope_case_id in case_ids_list:
                # Get case JSON.
                scope_case_json = siemplify._get_case_by_id(str(scope_case_id))

                # Extract scope alert from case json.
                for alert in scope_case_json['cyber_alerts']:
                    if alert_ticket_id.lower() == alert['external_id'].lower() and alert['additional_data']:
                        try:
                            siemplify.LOGGER.info('Found ticket with id: {0} for alert with ticket id: {1}'.format(
                                unicode(alert.get('additional_data')).encode('utf-8'),
                                unicode(alert.get('external_id')).encode('utf-8')
                            ))
                            connectwise_manager.close_ticket(alert['additional_data'],
                                                             custom_close_status="Completed")
                            siemplify.LOGGER.info('CW ticket with id: {0} closed successfully.'.format(
                                unicode(alert.get('additional_data')).encode('utf-8')))
                        except Exception as e:
                            # Write to log(Ticket does not exists anymore.)
                            siemplify.LOGGER.error(
                                'Ticket with id: {0} does not exists anymore or already closed. Error: {1}'.format(
                                    unicode(
                                        alert.get('additional_data')).encode(
                                        'utf-8'), e.message))

        siemplify.LOGGER.info(' +++ Dismiss Alerts In Siemplify. +++ ')

        #      Dismiss Alerts In Siemplify
        # =====================================

        # Get closed ticket ids from flat execution time.
        closed_tickets = connectwise_manager.get_close_tickets_since_time(last_execution_time,
                                                                          custom_close_status="Completed")
        siemplify.LOGGER.info('Got {0} closed tickets from CW since {1}.'.format(
            unicode(len(closed_tickets)).encode('utf-8'),
            unicode(last_execution_time).encode('utf-8')))

        for closed_ticket in closed_tickets:
            siemplify.LOGGER.info('Run on ticket with id: {0}'.format(unicode(closed_ticket['id']).encode('utf-8')))

            # Extract context case data.
            siemplify_alert_external_id = closed_ticket['summary']
            case_ids = siemplify.get_cases_by_ticket_id(siemplify_alert_external_id)
            siemplify.LOGGER.info('The following cases found for alert with ticket id {0}: {1}'.format(
                unicode(siemplify_alert_external_id).encode('utf-8'),
                unicode(case_ids).encode('utf-8')))

            # Dismiss alert.
            if case_ids:
                for case_id in case_ids:
                    # Get alert identifier.
                    scope_case_json = siemplify._get_case_by_id(str(case_id))
                    for alert in scope_case_json['cyber_alerts']:
                        if siemplify_alert_external_id.lower() == alert['external_id'].lower():
                            # Dismiss alert.
                            siemplify.dismiss_alert(alert['alert_group_identifier'], True, case_id)
                            siemplify.LOGGER.info('Alert with ticket id {0} was dismissed'.format(unicode(
                                alert['external_id']).encode('utf-8')))

        # Update Last Run Time.
        siemplify.save_timestamp(datetime_format=True)
        siemplify.LOGGER.info('--- JOB FINISHED. ---')

    except Exception as err:
        siemplify.LOGGER.error('Got exception on main handler.Error: {0}'.format(err.message))
        raise


if __name__ == '__main__':
    main()