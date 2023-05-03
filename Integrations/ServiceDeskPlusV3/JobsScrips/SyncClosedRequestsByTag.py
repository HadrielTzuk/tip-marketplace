from TIPCommon import extract_action_param
from constants import (
    INTEGRATION_NAME,
    SYNC_CLOSURE_SCRIPT_NAME,
    SERVICE_DESK_PLUS_TAG,
    REQUESTS_TAG,
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
from ServiceDeskPlusManagerV3 import ServiceDeskPlusManagerV3
from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler, convert_datetime_to_unix_time, unix_now
from utils import get_last_success_time
from ServiceDeskPlusV3Exceptions import NoteNotFoundException


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = SYNC_CLOSURE_SCRIPT_NAME
    siemplify.LOGGER.info('--------------- JOB STARTED ---------------')

    api_root = extract_action_param(siemplify=siemplify, param_name='Api Root', is_mandatory=True, print_value=True)
    api_key = extract_action_param(siemplify=siemplify, param_name='Api Key', is_mandatory=True, print_value=False)
    hours_backwards = extract_action_param(siemplify=siemplify, param_name='Max Hours Backwards', input_type=int,
                                           print_value=True, default_value=DEFAULT_HOURS_BACKWARDS)
    verify_ssl = extract_action_param(siemplify=siemplify, param_name="Verify SSL", default_value=True,
                                      input_type=bool, print_value=True)

    try:
        fetch_time = get_last_success_time(siemplify, offset_with_metric={'hours': hours_backwards}, print_value=False)
        fetch_time_ms = convert_datetime_to_unix_time(fetch_time)
        siemplify.LOGGER.info('Last fetch time. Date time:{}. Unix:{}'.format(fetch_time, fetch_time_ms))
        new_timestamp = unix_now()

        if hours_backwards < MIN_HOURS_BACKWARDS:
            raise Exception("\"Max Hours Backwards\" parameter must be greater or equal to {}".format(MIN_HOURS_BACKWARDS))

        servicedesk_manager = ServiceDeskPlusManagerV3(api_root=api_root, api_key=api_key, verify_ssl=verify_ssl)

        cases_id = siemplify.get_cases_by_filter(tags=[SERVICE_DESK_PLUS_TAG], statuses=[CASE_STATUS_CLOSED],
                                                 start_time_unix_time_in_ms=fetch_time_ms)

        closed_cases = []
        open_cases = []

        for case_id in cases_id:
            case = get_full_case_details(siemplify, case_id)
            closed_cases.append(case)

        siemplify.LOGGER.info(
            'Found {} closed cases with tag {} since last fetch time.'.format(len(closed_cases), SERVICE_DESK_PLUS_TAG))

        siemplify.LOGGER.info('--- Start Closing Requests in ServiceDeskPlus ---')

        for case in closed_cases:
            case_tags = [item.get("tag") for item in case.get("tags", []) if REQUESTS_TAG in item.get("tag")]
            request_ids = [tag.split(TAG_SEPARATOR)[1].strip() for tag in case_tags]
            request_id = next((id for id in request_ids if is_valid_request_id(siemplify, id)), None)
            if request_id:
                try:
                    servicedesk_manager.update_request_status(request_id, CLOSED_STATUS)
                    siemplify.LOGGER.info(
                        'ServiceDeskPlus request - {} status was updated to {}'.format(request_id, CLOSED_STATUS))
                except NoteNotFoundException:
                    siemplify.LOGGER.error('Job wasn\'t able to close the Request with ID {}. Reason: Request wasn\'t '
                                           'found in {}.'.format(request_id, INTEGRATION_NAME))
                except Exception as e:
                    siemplify.LOGGER.error('Failed to close the request {} in {}.'.format(request_id, INTEGRATION_NAME))
                    siemplify.LOGGER.exception(e)

        siemplify.LOGGER.info('--- Finished synchronizing closed cases from Siemplify to ServiceDeskPlus requests ---')

        cases_id = siemplify.get_cases_by_filter(tags=[SERVICE_DESK_PLUS_TAG], statuses=[CASE_STATUS_OPEN])
        for case_id in cases_id:
            case = get_full_case_details(siemplify, case_id)
            open_cases.append(case)

        siemplify.LOGGER.info(
            'Found {} open cases with tag {}.'.format(len(open_cases), SERVICE_DESK_PLUS_TAG))

        siemplify.LOGGER.info('--- Start Closing Alerts in Siemplify ---')

        for case in open_cases:
            case_tags = [item.get("tag") for item in case.get("tags", []) if REQUESTS_TAG in item.get("tag")]
            request_ids = [tag.split(TAG_SEPARATOR)[1].strip() for tag in case_tags]
            request_id = next((id for id in request_ids if is_valid_request_id(siemplify, id)), None)
            if request_id:
                try:
                    request = servicedesk_manager.get_request(request_id)
                    if request:
                        if request.status in [CLOSED_STATUS, CANCELLED_STATUS, RESOLVED_STATUS]:
                            case_id = case.get("id")
                            for alert in case.get("alerts", []):
                                alert_id = alert.get("identifier")
                                try:
                                    siemplify.close_alert(
                                        root_cause=ROOT_CAUSE,
                                        reason=REASON,
                                        comment=COMMENT.format(status=request.status),
                                        case_id=case_id,
                                        alert_id=alert_id
                                    )
                                    siemplify.LOGGER.info('Alert {} was closed'.format(alert_id))
                                except Exception as error:
                                    siemplify.LOGGER.error(f"Failed to close alert {alert_id} of case {case_id}")
                                    siemplify.LOGGER.exception(error)
                except NoteNotFoundException:
                    siemplify.LOGGER.error(
                        'Job wasn\'t able to get details for the Request with ID {}. Reason: Request wasn\'t '
                        'found in {}.'.format(request_id, INTEGRATION_NAME))
                except Exception as e:
                    siemplify.LOGGER.error('Failed to get details for the request {} from {}.'.format(request_id,
                                                                                                      INTEGRATION_NAME))
                    siemplify.LOGGER.exception(e)

        siemplify.save_timestamp(new_timestamp=new_timestamp)
        siemplify.LOGGER.info(' --- Finish synchronize closed requests from ServiceDeskPlus to Siemplify cases --- ')
        siemplify.LOGGER.info('--------------- JOB FINISHED ---------------')

    except Exception as error:
        siemplify.LOGGER.error(f'Got exception on main handler. Error: {error}')
        siemplify.LOGGER.exception(error)
        raise


def get_full_case_details(siemplify, case_id):
    address = "{0}/{1}/{2}{3}".format(siemplify.sdk_config.api_root_uri, "external/v1/cases/GetCaseFullDetails",
                                      case_id, "?format=snake")
    response = siemplify.session.get(address)
    siemplify.validate_siemplify_error(response)
    return response.json()


def is_valid_request_id(siemplify, request_id):
    try:
        request_id = int(request_id)
    except Exception:
        siemplify.LOGGER.error(f"Request id: {request_id} is in invalid format.")
        return False

    if request_id < 1:
        siemplify.LOGGER.error(f"Request id should be a positive number.")
        return False
    return True


if __name__ == '__main__':
    main()
