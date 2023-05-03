import datetime
import requests
import urllib3
from QRadarManager import QRadarManager
from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import convert_datetime_to_unix_time, utc_now
from SiemplifyUtils import output_handler
from constants import SYNC_CLOSURE_JOB_SCRIPT_NAME, SIEMPLIFY_CLOSE_REASON, DEFAULT_DAYS_BACKWARDS, PROVIDER_NAME

CLOSE_CASE_STATUS = 'CLOSE'
CLOSE_CASES_MAX_RESULTS = 10000


def validate_timestamp(last_run_timestamp, offset):
    """
    Validate timestamp in range
    :param last_run_timestamp: {datetime} last run timestamp
    :param offset: {datetime} last run timestamp
    :return: {datetime} if first run, return current time minus offset time, else return timestamp from file
    """
    current_time = utc_now()
    # Check if first run
    if current_time - last_run_timestamp > datetime.timedelta(days=offset):
        return current_time - datetime.timedelta(days=offset)
    else:
        return last_run_timestamp


def validate_close_reason_id(qradar_manager):
    """
    You must provide a valid closing_reason_id when you close an offense.
    :param qradar_manager: instance to qradar manager
    :return: {int} close reason id
    """
    reasons = qradar_manager.get_all_closing_reasons()
    for reason in reasons:
        # Return existing id of close reason
        if reason.text == SIEMPLIFY_CLOSE_REASON:
            return reason.id
    # Otherwise Siemplify custom reason not exist. Create one and return its id.
    return qradar_manager.create_close_reason().id


def get_case_and_offense_ids(case):
    """
    Extract incident case offense ids
    :param case: cases object
    :return: {dict} Dict of {case id, offense id, is test case}
    """
    case_alert_ids = {}
    for alert in case.get('cyber_alerts', []):
        case_id = case.get('identifier')
        ticket_id = alert.get('additional_properties', {}).get('TicketId')
        offense_id = alert.get('additional_properties', {}).get('offense_id') or alert.get('additional_properties', {}).get('OFFENSE_ID')
        is_test_case = alert.get('additional_properties', {}).get('IsTestCase')

        if not offense_id:
            continue

        case_alert_ids = {"case_id": case_id, "offense_id": offense_id, "ticket_id": ticket_id,
                          "is_test_case": is_test_case}
    return case_alert_ids


@output_handler
def main():
    siemplify = SiemplifyJob()

    try:
        siemplify.script_name = SYNC_CLOSURE_JOB_SCRIPT_NAME

        api_root = siemplify.extract_job_param(param_name='API Root', is_mandatory=True)
        api_token = siemplify.extract_job_param(param_name='API Token', is_mandatory=True)
        api_version = siemplify.extract_job_param(param_name='API Version')
        days_backwards = siemplify.extract_job_param(param_name='Days Backwards', input_type=int,
                                                     default_value=DEFAULT_DAYS_BACKWARDS)

        siemplify.LOGGER.info('--------------- JOB STARTED ---------------')

        manager = QRadarManager(api_root, api_token, api_version)
        # Validate that simeplify close reason exists in qradar instance
        close_reason_id = validate_close_reason_id(manager)

        # Get last Successful execution time.
        last_successful_execution_time = siemplify.fetch_timestamp(datetime_format=True)
        last_successful_execution_time = validate_timestamp(last_successful_execution_time, days_backwards)
        unix_last_successful_execution = convert_datetime_to_unix_time(last_successful_execution_time)
        siemplify.LOGGER.info(
            'Last successful execution run: {}'.format(str(last_successful_execution_time)))

        siemplify.LOGGER.info('--- Start Closing Offenses in Qradar ---')

        # Get all closed case ids
        closed_cases_ids = siemplify.get_cases_ids_by_filter(
            status=CLOSE_CASE_STATUS,
            close_time_from_unix_time_in_ms=unix_last_successful_execution,
            max_results=CLOSE_CASES_MAX_RESULTS
        )

        # Get all closed cases and their relevant details
        closed_cases = [siemplify._get_case_by_id(case_id) for case_id in closed_cases_ids]
        cases_and_offenses = [get_case_and_offense_ids(item) for item in closed_cases]

        # Get all scope alerts.
        closed_cases_alerts_ids = siemplify.get_alerts_ticket_ids_from_cases_closed_since_timestamp(
            unix_last_successful_execution, None)

        # Filter out test cases
        non_test_cases = [item for item in cases_and_offenses if item.get("is_test_case") == 'False']
        closed_cases_alerts_ids = [item.get("offense_id") for item in non_test_cases
                                   if item.get("ticket_id") in closed_cases_alerts_ids]

        # Save current time at timestamp to make sure all alerts are taken.
        new_timestamp = utc_now()

        siemplify.LOGGER.info("Found {} closed alerts".format(len(closed_cases_alerts_ids)))

        # In Qradar alerts ticket ids are the related offenses ids
        qradar_offenses = closed_cases_alerts_ids

        for offense_id in qradar_offenses:
            try:
                manager.close_offense(offense_id, close_reason_id)
                siemplify.LOGGER.info("Qradar offense - {} was closed".format(offense_id))

            except Exception as e:
                siemplify.LOGGER.error('Failed to close offense {}. Error: {}.'.format(offense_id, str(e)))

        siemplify.LOGGER.info(" --- Finish synchronize closure from Siemplify to Qradar offenses --- ")

        # Update last successful run time with new_timestamp
        siemplify.save_timestamp(new_timestamp)
        siemplify.LOGGER.info("Update Job last execution timestamp")
        siemplify.LOGGER.info('--------------- JOB FINISHED ---------------')

    except Exception as err:
        siemplify.LOGGER.exception('Got exception on main handler.Error: {}'.format(err))
        raise


if __name__ == '__main__':
    main()
