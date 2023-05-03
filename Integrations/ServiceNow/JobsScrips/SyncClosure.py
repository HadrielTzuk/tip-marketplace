from ServiceNowManager import ServiceNowManager, ServiceNowRecordNotFoundException
from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler, utc_now, convert_datetime_to_unix_time
from constants import INTEGRATION_NAME, PRODUCT_NAME, SYNC_CLOSURE, CASE_RULE_GENERATOR, STATES, RESOLVED, CLOSED, \
    CANCELED, STATES_NAMES, INCIDENT_NUMBER_PREFIX
from UtilsManager import validate_timestamp, get_incidents_numbers_from_case, get_case_and_alerts_ids

# =====================================
#             CONSTANTS               #
# =====================================
OPEN_CASE_STATUS = '1'
CLOSE_CASE_STATUS = '2'
CLOSE_INCIDENT_REASON = 'Closed By Siemplify'
CLOSE_INCIDENT_CODE = 'Closed/Resolved by Caller'
NO_INCIDENTS_FOUND = 'No Record found'

ROOT_CAUSE = 'None'
CLOSE_ALERT_REASON = 'Maintenance'
CLOSE_ALERT_COMMENT = '{} in ServiceNow'
DEFAULT_HOURS_BACKWARD = 24

INCIDENT_STATES_FOR_CLOSE_ALERT = [
    STATES[RESOLVED],
    STATES[CLOSED],
    STATES[CANCELED]
]


def close_incidents_in_servicenow(siemplify, sn_manager, last_execution_time):
    """
    Close incidents in ServiceNow if they are closed in Siemplify
    :param siemplify: {SiemplifyJob} Instance of class SiemplifyJob
    :param sn_manager: {ServiceNowManager} Instance of class ServiceNowManager
    :param last_execution_time: {float} Last job execution time
    """
    siemplify.LOGGER.info('--- Start synchronize closure from Siemplify to ServiceNow ---')

    last_execution_time_sn = sn_manager.convert_datetime_to_sn_format(last_execution_time)

    ticket_ids_for_closed_cases = siemplify.get_alerts_ticket_ids_from_cases_closed_since_timestamp(
        int(last_execution_time.timestamp() * 1000), CASE_RULE_GENERATOR)

    siemplify.save_timestamp(new_timestamp=utc_now())

    closed_cases = []

    for ticket_id in ticket_ids_for_closed_cases:
        try:
            closed_cases.extend(
                [siemplify._get_case_by_id(case_id) for case_id in siemplify.get_cases_by_ticket_id(ticket_id)]
            )
        except Exception as e:
            siemplify.LOGGER.error('Failed to fetch case with ticket id {}. Reason {}'.format(ticket_id, e))

    siemplify.LOGGER.info('Found {} closed cases since {}'.format(len(closed_cases), last_execution_time_sn))

    incidents_numbers_to_close = [incident_number for case in closed_cases
                                  for incident_number in get_incidents_numbers_from_case(case, INCIDENT_NUMBER_PREFIX)]

    if not incidents_numbers_to_close:
        return

    try:
        incidents_to_close = sn_manager.get_incidents(numbers=incidents_numbers_to_close,
                                                      states=INCIDENT_STATES_FOR_CLOSE_ALERT, state_match=False,
                                                      fields=['sys_id', 'state', 'number'])

        for incident in incidents_to_close:
            try:
                sn_manager.close_incident(incident.number,
                                          CLOSE_INCIDENT_REASON,
                                          close_notes=CLOSE_INCIDENT_REASON,
                                          close_code=CLOSE_INCIDENT_CODE)
                siemplify.LOGGER.info('Incident {} closed in Service now'.format(incident.number))
            except Exception as e:
                siemplify.LOGGER.error('Failed to close incident {}. Reason: {}'.format(incident.number, e))

    except Exception as e:
        siemplify.LOGGER.error('Failed to fetch incidents Reason: {0}'.format(e))

    siemplify.LOGGER.info('--- Finish synchronize closure from Siemplify to ServiceNow ---')


def close_cases_in_siemplify(siemplify, sn_manager):
    """
    Close cases in Siemplify if they are closed in ServiceNow
    :param siemplify: {SiemplifyJob} Instance of class SiemplifyJob
    :param sn_manager: {ServiceNowManager} Instance of class ServiceNowManager
    """
    siemplify.LOGGER.info('--- Start synchronize closure from ServiceNow to Siemplify ---')

    open_cases = [siemplify._get_case_by_id(case_id) for case_id in
                  siemplify.get_cases_by_filter(case_names=[PRODUCT_NAME], statuses=[OPEN_CASE_STATUS])]

    siemplify.LOGGER.info('Found {} open cases'.format(len(open_cases)))

    incident_number_open_case_map = {incident_number: case for case in open_cases
                                     for incident_number in
                                     get_incidents_numbers_from_case(case, INCIDENT_NUMBER_PREFIX)}

    closed_incidents_in_sn = []
    closed_incidents_in_siemplify = []

    if incident_number_open_case_map:
        try:
            closed_incidents_in_sn = sn_manager.get_incidents(numbers=incident_number_open_case_map.keys(),
                                                              states=INCIDENT_STATES_FOR_CLOSE_ALERT,
                                                              state_match=True,
                                                              fields=['sys_id', 'state', 'number'])

            siemplify.LOGGER.info('Found {} closed incidents in Service now'.format(len(closed_incidents_in_sn)))
        except ServiceNowRecordNotFoundException:
            siemplify.LOGGER.info('Not found incidents for opened cases')
        except Exception as e:
            siemplify.LOGGER.exception(e)
            siemplify.LOGGER.error('Failed to fetch incidents. Reason: {}'.format(e))

        for incident in closed_incidents_in_sn:
            case = incident_number_open_case_map[incident.number]
            for case_id, alert_ids in get_case_and_alerts_ids(case).items():
                for alert_id in alert_ids:
                    try:
                        siemplify.close_alert(
                            case_id=case_id,
                            alert_id=alert_id,
                            root_cause=ROOT_CAUSE,
                            reason=CLOSE_ALERT_REASON,
                            comment=CLOSE_ALERT_COMMENT.format(STATES_NAMES.get(int(incident.state)))
                        )
                        closed_incidents_in_siemplify.append(incident.number)
                        siemplify.LOGGER.info('Alert for incident {} was closed'.format(incident.number))
                    except Exception as e:
                        siemplify.LOGGER.exception(e)
                        siemplify.LOGGER.error('Failed to close alert for incident {} Reason: {}.'
                                               .format(incident.number, e))

    siemplify.LOGGER.info('--- Finish synchronize closure from ServiceNow to Siemplify ---')


@output_handler
def main():
    siemplify = SiemplifyJob()

    try:
        siemplify.script_name = SYNC_CLOSURE

        siemplify.LOGGER.info('--------------- JOB STARTED ---------------')

        api_root = siemplify.extract_job_param(param_name='Api Root', is_mandatory=True)
        username = siemplify.extract_job_param(param_name='Username', is_mandatory=True)
        password = siemplify.extract_job_param(param_name='Password', is_mandatory=True)
        verify_ssl = siemplify.extract_job_param(param_name='Verify SSL', is_mandatory=True, input_type=bool)
        client_id = siemplify.extract_job_param(param_name="Client ID", is_mandatory=False)
        client_secret = siemplify.extract_job_param(param_name="Client Secret", is_mandatory=False)
        refresh_token = siemplify.extract_job_param(param_name="Refresh Token", is_mandatory=False)
        use_oauth = siemplify.extract_job_param(param_name="Use Oauth Authentication", default_value=False,
                                                input_type=bool, is_mandatory=False)
        table_name = siemplify.extract_job_param(param_name='Table Name', is_mandatory=True)
        hours_backwards = siemplify.extract_job_param(param_name='Max Hours Backwards', is_mandatory=False,
                                                      input_type=int, default_value=DEFAULT_HOURS_BACKWARD)

        service_now_manager = ServiceNowManager(api_root=api_root, username=username, password=password,
                                                default_incident_table=table_name, verify_ssl=verify_ssl,
                                                siemplify_logger=siemplify.LOGGER, client_id=client_id,
                                                client_secret=client_secret, refresh_token=refresh_token,
                                                use_oauth=use_oauth)

        last_successful_execution_time = validate_timestamp(siemplify.fetch_timestamp(datetime_format=True),
                                                            hours_backwards)

        close_incidents_in_servicenow(siemplify, service_now_manager, last_successful_execution_time)
        close_cases_in_siemplify(siemplify, service_now_manager)

        siemplify.LOGGER.info('--------------- JOB FINISHED ---------------')
    except Exception as e:
        siemplify.LOGGER.error('Got exception on main handler.Error: {0}'.format(e))
        siemplify.LOGGER.exception(e)


if __name__ == '__main__':
    main()
