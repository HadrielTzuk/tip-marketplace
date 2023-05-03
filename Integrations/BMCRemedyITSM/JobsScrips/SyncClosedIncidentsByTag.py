from TIPCommon import extract_action_param
from constants import (
    INTEGRATION_NAME,
    SYNC_CLOSURE_SCRIPT_NAME,
    BMC_REMEDY_ITSM_TAG,
    INCIDENTS_TAG,
    TAG_SEPARATOR,
    CANCELLED_STATUS,
    CLOSED_STATUS,
    RESOLVED_STATUS,
    REASON,
    ROOT_CAUSE,
    COMMENT,
    CASE_STATUS_CLOSED,
    CASE_STATUS_OPEN,
    DEFAULT_HOURS_BACKWARDS,
    MIN_HOURS_BACKWARDS
)
from BMCRemedyITSMManager import BMCRemedyITSMManager
from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler, unix_now
from UtilsManager import get_last_success_time, UNIX_FORMAT
from BMCRemedyITSMExceptions import BMCRemedyITSMNotFoundException, BMCRemedyITSMJobException


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = SYNC_CLOSURE_SCRIPT_NAME
    siemplify.LOGGER.info('--------------- JOB STARTED ---------------')

    api_root = extract_action_param(siemplify=siemplify, param_name='API Root', is_mandatory=True, print_value=True)
    username = extract_action_param(siemplify=siemplify, param_name='Username', is_mandatory=True, print_value=True)
    password = extract_action_param(siemplify=siemplify, param_name='Password', is_mandatory=True, print_value=False)
    hours_backwards = extract_action_param(siemplify=siemplify, param_name='Max Hours Backwards', input_type=int,
                                           print_value=True, default_value=DEFAULT_HOURS_BACKWARDS)
    verify_ssl = extract_action_param(siemplify=siemplify, param_name="Verify SSL", default_value=True,
                                      input_type=bool, print_value=True)
    incident_table = extract_action_param(siemplify=siemplify, param_name='Incident Table', is_mandatory=True,
                                          print_value=True)
    manager = None

    try:
        fetch_time_ms = get_last_success_time(siemplify, offset_with_metric={'hours': hours_backwards},
                                              time_format=UNIX_FORMAT)

        if hours_backwards < MIN_HOURS_BACKWARDS:
            raise Exception("\"Max Hours Backwards\" parameter must be greater or equal to {}".format(
                MIN_HOURS_BACKWARDS))

        manager = BMCRemedyITSMManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl,
                                       siemplify_logger=siemplify.LOGGER)

        cases_id = siemplify.get_cases_by_filter(tags=[BMC_REMEDY_ITSM_TAG], statuses=[CASE_STATUS_CLOSED],
                                                 start_time_unix_time_in_ms=fetch_time_ms)

        closed_cases = []
        open_cases = []

        for case_id in cases_id:
            case = get_full_case_details(siemplify, case_id)
            closed_cases.append(case)

        siemplify.LOGGER.info(
            'Found {} closed cases with tag {} since last fetch time.'.format(len(closed_cases), BMC_REMEDY_ITSM_TAG))

        siemplify.LOGGER.info(f'--- Start Closing Incidents in {INTEGRATION_NAME} ---')

        for case in closed_cases:
            case_tags = [item.get("tag") for item in case.get("tags", []) if INCIDENTS_TAG in item.get("tag")]
            request_ids = [tag.split(TAG_SEPARATOR)[1].strip() for tag in case_tags]
            if request_ids:
                request_id = request_ids[0]
                try:
                    incidents = manager.get_incident_details_by_table(table_name=incident_table, incident_id=request_id)
                    if incidents:
                        incident = incidents[0]
                        if incident.status in [CLOSED_STATUS, CANCELLED_STATUS, RESOLVED_STATUS]:
                            siemplify.LOGGER.info(
                                'Incident - {} status is {}. Skipping...'.format(request_id, incident.status))
                        else:
                            manager.update_incident_by_table(request_id=incident.request_id, table_name=incident_table)
                            siemplify.LOGGER.info(
                                'Incident - {} status was updated to {}'.format(request_id, CLOSED_STATUS))
                    else:
                        siemplify.LOGGER.error(
                            'Job wasn\'t able to get details for the Incident with ID {}. Reason: Incident wasn\'t '
                            'found in {}.'.format(request_id, INTEGRATION_NAME))
                except BMCRemedyITSMNotFoundException:
                    siemplify.LOGGER.error('Job wasn\'t able to close the Incident with ID {}. Reason: Incident '
                                           'wasn\'t found in {}.'.format(request_id, INTEGRATION_NAME))
                except BMCRemedyITSMJobException:
                    siemplify.LOGGER.error(
                        "Job wasn't able to close the incident \"{}\". Reason: assignee or assignee group "
                        "wasn't provided in the incident. Please add them via \"Update Incident\" actions.".format(
                            request_id))
                except Exception as e:
                    siemplify.LOGGER.error('Failed to close the incident {} in {}.'.format(request_id, INTEGRATION_NAME))
                    siemplify.LOGGER.exception(e)

        siemplify.LOGGER.info(f'--- Finished synchronizing closed cases from Siemplify to {INTEGRATION_NAME} '
                              f'incidents ---')

        cases_id = siemplify.get_cases_by_filter(tags=[BMC_REMEDY_ITSM_TAG], statuses=[CASE_STATUS_OPEN])
        for case_id in cases_id:
            case = get_full_case_details(siemplify, case_id)
            open_cases.append(case)

        siemplify.LOGGER.info(
            'Found {} open cases with tag {}.'.format(len(open_cases), BMC_REMEDY_ITSM_TAG))

        siemplify.LOGGER.info('--- Start Closing Alerts in Siemplify ---')

        for case in open_cases:
            case_tags = [item.get("tag") for item in case.get("tags", []) if INCIDENTS_TAG in item.get("tag")]
            request_ids = [tag.split(TAG_SEPARATOR)[1].strip() for tag in case_tags]
            if request_ids:
                request_id = request_ids[0]
                try:
                    incidents = manager.get_incident_details_by_table(table_name=incident_table, incident_id=request_id)
                    if incidents:
                        incident = incidents[0]
                        if incident.status in [CLOSED_STATUS, CANCELLED_STATUS, RESOLVED_STATUS]:
                            case_id = case.get("id")
                            for alert in case.get("alerts", []):
                                alert_id = alert.get("identifier")
                                try:
                                    siemplify.close_alert(
                                        root_cause=ROOT_CAUSE,
                                        reason=REASON,
                                        comment=COMMENT.format(status=incident.status),
                                        case_id=case_id,
                                        alert_id=alert_id
                                    )
                                    siemplify.LOGGER.info('Alert {} was closed'.format(alert_id))
                                except Exception as error:
                                    siemplify.LOGGER.error(f"Failed to close alert {alert_id} of case {case_id}")
                                    siemplify.LOGGER.exception(error)
                    else:
                        siemplify.LOGGER.error(
                            'Job wasn\'t able to get details for the Incident with ID {}. Reason: Incident wasn\'t '
                            'found in {}.'.format(request_id, INTEGRATION_NAME))
                except BMCRemedyITSMNotFoundException:
                    siemplify.LOGGER.error(
                        'Job wasn\'t able to get details for the Incident with ID {}. Reason: Incident wasn\'t '
                        'found in {}.'.format(request_id, INTEGRATION_NAME))
                except Exception as e:
                    siemplify.LOGGER.error('Failed to get details for the incident {} from {}.'.format(
                        request_id, INTEGRATION_NAME))
                    siemplify.LOGGER.exception(e)
        all_cases = sorted(closed_cases, key=lambda case: case.get('creation_time_unix_time_in_ms', 1))
        new_timestamp = all_cases[-1].get('creation_time_unix_time_in_ms', 1) + 1 if all_cases else unix_now()
        siemplify.save_timestamp(new_timestamp=new_timestamp)
        siemplify.LOGGER.info(f' --- Finish synchronize closed incidents from {INTEGRATION_NAME} to Siemplify cases --- ')
        siemplify.LOGGER.info('--------------- JOB FINISHED ---------------')

    except Exception as error:
        siemplify.LOGGER.error(f'Got exception on main handler. Error: {error}')
        siemplify.LOGGER.exception(error)
        raise

    finally:
        try:
            if manager:
                siemplify.LOGGER.info(f"Logging out from {INTEGRATION_NAME}..")
                manager.logout()
                siemplify.LOGGER.info(f"Successfully logged out from {INTEGRATION_NAME}")
        except Exception as error:
            siemplify.LOGGER.error(f"Logging out failed. Error: {error}")
            siemplify.LOGGER.exception(error)


def get_full_case_details(siemplify, case_id):
    address = "{0}/{1}/{2}{3}".format(siemplify.sdk_config.api_root_uri, "external/v1/cases/GetCaseFullDetails",
                                      case_id, "?format=snake")
    response = siemplify.session.get(address)
    siemplify.validate_siemplify_error(response)
    return response.json()


if __name__ == '__main__':
    main()
