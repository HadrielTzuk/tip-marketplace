import urllib3
import requests
from SiemplifyUtils import output_handler, convert_string_to_datetime
from SiemplifyJob import SiemplifyJob
from LogRhythmManager import LogRhythmRESTManager
from SiemplifyUtils import convert_unixtime_to_datetime, utc_now, convert_datetime_to_unix_time
from constants import SYNC_CASE_COMMENTS_SCRIPT_NAME, DEFAULT_DEVICE_PRODUCT, CASE_STATUS_OPEN, LOGRHYTHM_COMMENT_PREFIX, \
    SIEMPLIFY_COMMENT_PREFIX
from exceptions import LogRhythmManagerBadRequestError


@output_handler
def main():
    siemplify = SiemplifyJob()

    try:
        siemplify.script_name = SYNC_CASE_COMMENTS_SCRIPT_NAME

        api_root = siemplify.extract_job_param(param_name='Api Root', is_mandatory=True)
        api_token = siemplify.extract_job_param(param_name='Api Token', is_mandatory=True)
        verify_ssl = siemplify.extract_job_param(param_name='Verify SSL', is_mandatory=True, input_type=bool)

        siemplify.LOGGER.info('--------------- JOB STARTED ---------------')

        manager = LogRhythmRESTManager(api_root=api_root, api_key=api_token, verify_ssl=verify_ssl,
                                       force_check_connectivity=True)
        last_successful_execution_time = siemplify.fetch_timestamp(datetime_format=True)

        new_timestamp = utc_now()

        fetched_open_cases_ids = siemplify.get_cases_by_filter(statuses=[CASE_STATUS_OPEN],
                                                               case_names=[DEFAULT_DEVICE_PRODUCT])

        siemplify.LOGGER.info('--- Start synchronize cases Comments from Siemplify to LogRhythm ---')

        for case_id in fetched_open_cases_ids:
            case = siemplify._get_case_by_id(case_id)
            case_identifier = case.get("identifier")
            siemplify.LOGGER.info(f'Run on case with id: {case_identifier}')
            case_comments = siemplify.get_case_comments(case_identifier)
            siemplify.LOGGER.info(f"Found {len(case_comments)} comments for case with id: {case_identifier}")
            for comment in case_comments:
                comment_time = convert_unixtime_to_datetime((comment.get('modification_time_unix_time_in_ms', 0)))
                if comment_time < last_successful_execution_time or comment.get("comment").startswith(LOGRHYTHM_COMMENT_PREFIX):
                    continue
                siemplify.LOGGER.info(f"Found new comment at Case {case_identifier}")

                comment_text = f"{SIEMPLIFY_COMMENT_PREFIX}{comment.get('comment')}"
                for alert in case.get('cyber_alerts', []):
                    case_number = None
                    if alert.get('reporting_product') == DEFAULT_DEVICE_PRODUCT:
                        if alert.get('additional_properties', {}).get('number') is not None:
                            case_number = alert.get('additional_properties', {}).get('TicketId')
                    else:
                        case_number = alert.get('additional_data')
                    if case_number:
                        try:
                            manager.add_note_to_case(case_id=case_number, note=comment_text)
                            siemplify.LOGGER.info(f"Add comment to case {case_number}")
                        except LogRhythmManagerBadRequestError as err:
                            siemplify.LOGGER.info(f"Case with ID {case_number} is closed. Can't sync the comments.")
                            continue
                        except Exception as err:
                            siemplify.LOGGER.error(f"Failed to add comment to ticket {case_number}, error: {err}")
                            siemplify.LOGGER.exception(err)
                    else:
                        siemplify.LOGGER.info(f"Cannot find issue key. Comments from case {case_identifier} not added "
                                              f"to issue")
        siemplify.LOGGER.info(" --- Finish synchronize comments from cases to LogRhythm cases --- ")

        siemplify.LOGGER.info('--- Start synchronize case Comments from LogRhythm to Siemplify ---')
        for case_id in fetched_open_cases_ids:
            case = siemplify._get_case_by_id(case_id)
            case_identifier = case.get("identifier")
            for alert in case.get('cyber_alerts', []):
                case_number = None
                if alert.get('reporting_product') == DEFAULT_DEVICE_PRODUCT:
                    if alert.get('additional_properties', {}).get('number') is not None:
                        case_number = alert.get('additional_properties', {}).get('TicketId')
                else:
                    case_number = alert.get('additional_data')
                if case_number:
                    try:
                        notes = manager.get_case_evidence(case_id=case_number, status_filter="completed",
                                                          type_filter="note")
                        if notes:
                            notes = sorted(notes, key=lambda note: note.date_created)
                            comments_to_add = [note for note in notes if not
                            (note.context).startswith(SIEMPLIFY_COMMENT_PREFIX)]
                            comments_to_add = [note.context for note in comments_to_add
                                               if convert_string_to_datetime(
                                    note.date_created) >= last_successful_execution_time and convert_string_to_datetime(
                                    note.date_created) < new_timestamp]
                            if comments_to_add:
                                siemplify.LOGGER.info(f'Add comments to case with id: {case_identifier}')
                                for comment in comments_to_add:
                                    comment_with_prefix = f"{LOGRHYTHM_COMMENT_PREFIX}{comment}"
                                    siemplify.add_comment(comment_with_prefix, case_identifier, None)
                                siemplify.LOGGER.info("Comments were added successfully")
                            else:
                                siemplify.LOGGER.info(f"No new comments in case - {case_identifier}")
                        else:
                            siemplify.LOGGER.info(f"No new comments in case -{case_identifier}")
                    except Exception as err:
                        siemplify.LOGGER.error(f'Failed to get details for case {case_number}.')
                        siemplify.LOGGER.exception(err)
                else:
                    siemplify.LOGGER.info(f"Cannot find issue key. Comments from case {case_identifier} not added "
                                          f"to issue")
        siemplify.LOGGER.info(" --- Finish synchronize case Comments from LogRhythm to Siemplify --- ")
        siemplify.save_timestamp(new_timestamp=new_timestamp)
        siemplify.LOGGER.info('--------------- JOB FINISHED ---------------')
    except Exception as err:
        siemplify.LOGGER.exception(f"Got exception on main handler.Error: {err}")
        raise


if __name__ == '__main__':
    main()
