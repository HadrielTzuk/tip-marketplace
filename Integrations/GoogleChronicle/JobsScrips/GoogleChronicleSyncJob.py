from TIPCommon import extract_action_param
from consts import (
    SYNC_DATA_SCRIPT_NAME,
    DEFAULT_HOURS_BACKWARDS,
    MAX_FETCH_LIMIT_FOR_JOB,
    UNIFIED_CONNECTOR_DEVICE_VENDOR,
    INTEGRATION_DISPLAY_NAME
)
from GoogleChronicleManager import GoogleChronicleManager
from SiemplifyDataModel import SyncCaseIdMatch
from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler, unix_now
from utils import (
    get_last_success_time_for_job,
    save_timestamp_for_job,
    read_ids_for_job,
    write_ids_for_job,
    UNIX_FORMAT,
    platform_supports_chronicle
)
import json


CASE_IDS_DB_KEY = "pending_case_ids"
ALERT_IDS_DB_KEY = "pending_alert_ids"
CASES_TIMESTAMP_DB_KEY = "cases_timestamp"
ALERTS_TIMESTAMP_DB_KEY = "alerts_timestamp"
MAX_RETRIES_NUMBER = 5
MINIMUM_SUPPORTED_VERSION = "6.1.44"


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = SYNC_DATA_SCRIPT_NAME
    siemplify.LOGGER.info('--------------- JOB STARTED ---------------')

    environment = extract_action_param(siemplify=siemplify, param_name='Environment', is_mandatory=True,
                                       print_value=True, default_value='Default Environment')
    api_root = extract_action_param(siemplify=siemplify, param_name='API Root', is_mandatory=True, print_value=True)
    creds = extract_action_param(siemplify=siemplify, param_name="User's Service Account", is_mandatory=True,
                                 print_value=False)
    hours_backwards = extract_action_param(siemplify=siemplify, param_name='Max Hours Backwards', input_type=int,
                                           print_value=True, default_value=DEFAULT_HOURS_BACKWARDS)
    verify_ssl = extract_action_param(siemplify=siemplify, param_name="Verify SSL", default_value=True,
                                      input_type=bool, print_value=True)

    try:
        creds = json.loads(creds)
    except Exception as e:
        siemplify.LOGGER.error("Unable to parse credentials as JSON. Please validate creds.")
        siemplify.LOGGER.exception(e)
        raise

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        if hours_backwards < 1:
            raise Exception("\"Max Hours Backwards\" parameter must be a positive number.")

        if not platform_supports_chronicle(siemplify):
            raise Exception(f"Current platform version does not support SDK methods designed for "
                            f"{INTEGRATION_DISPLAY_NAME}. Please use version {MINIMUM_SUPPORTED_VERSION} or higher.")

        manager = GoogleChronicleManager(api_root=api_root, verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER,
                                         **creds)
        manager.test_connectivity()

        siemplify.LOGGER.info(f'--- Start Processing Updated Cases ---')

        cases_last_success_timestamp = get_last_success_time_for_job(
            siemplify=siemplify,
            offset_with_metric={"hours": hours_backwards},
            time_format=UNIX_FORMAT,
            timestamp_key=CASES_TIMESTAMP_DB_KEY
        )

        pending_case_ids = read_ids_for_job(siemplify, CASE_IDS_DB_KEY, default_value_to_return=[])
        siemplify.LOGGER.info(f"Successfully loaded {len(pending_case_ids)} pending case ids")

        cases_count = MAX_FETCH_LIMIT_FOR_JOB - len(pending_case_ids)
        if cases_count <= 0:
            if cases_count < 0:
                siemplify.LOGGER.error(f"Cases overload: case limit is {MAX_FETCH_LIMIT_FOR_JOB}. "
                                       f"{abs(cases_count)} cases will not be synced")
                pending_case_ids = pending_case_ids[:MAX_FETCH_LIMIT_FOR_JOB]
            cases_metadata = []
        else:
            cases_metadata = manager.get_updated_cases_metadata(
                siemplify=siemplify,
                start_timestamp_unix_ms=cases_last_success_timestamp,
                count=cases_count,
                allowed_environments=[environment],
                vendor=UNIFIED_CONNECTOR_DEVICE_VENDOR
            )
            siemplify.LOGGER.info(
                'Found {} updated cases since last fetch time.'.format(len(cases_metadata)))

        case_ids = [pending_case_id.get('id') for pending_case_id in pending_case_ids]
        case_ids += [metadata.id for metadata in cases_metadata]
        case_ids = list(set(case_ids))
        cases_with_details = siemplify.get_sync_cases(case_ids)
        chronicle_cases = manager.convert_siemplify_cases_to_chronicle(cases_with_details)
        successful_cases = []
        failed_cases = []
        cases_to_remove_from_backlog = []

        if case_ids:
            siemplify.LOGGER.info(f'--- Start Updating Cases in Chronicle ---')
            siemplify.LOGGER.info(f'Case ids to be updated: {case_ids}')
            try:
                updated_chronicle_cases = manager.batch_update_cases_in_chronicle(chronicle_cases)

                for case in updated_chronicle_cases:
                    if case.has_failed:
                        failed_cases.append(case)
                    else:
                        successful_cases.append(case)

                for failed_case in failed_cases:
                    pending_case = next((item for item in pending_case_ids if item.get('id') == failed_case.id), {})
                    retries_counter = pending_case.get('retries', 0)
                    if retries_counter >= MAX_RETRIES_NUMBER:
                        siemplify.LOGGER.info(f"Max retries reached for case {failed_case.id}. Removing from backlog.")
                        cases_to_remove_from_backlog.append(failed_case.id)
                        continue
                    else:
                        if pending_case:
                            pending_case["retries"] += 1
                        else:
                            pending_case_ids.append({"id": failed_case.id, "retries": 1})

                if failed_cases:
                    siemplify.LOGGER.info(
                        f"The following cases were not synced: {', '.join([str(failed.id) for failed in failed_cases])}. ")

                case_id_matches = []
                for successful_case in successful_cases:
                    ids = [case.get("id") for case in pending_case_ids]
                    if successful_case.id in ids:
                        cases_to_remove_from_backlog.append(successful_case.id)

                    for chr_case in chronicle_cases:
                        if successful_case.id == chr_case.id and chr_case.external_id in ["None", None, ""]:
                            case_id_matches.append(
                                SyncCaseIdMatch(successful_case.id, successful_case.external_id))
                try:
                    updated_case_ids = siemplify.batch_update_case_id_matches(case_id_matches)
                    siemplify.LOGGER.info(f'Updated External Case Ids for the following cases: {updated_case_ids}')
                except Exception as e:
                    siemplify.LOGGER.error('Failed to update external ids.')
                    siemplify.LOGGER.exception(e)
            except Exception as e:
                siemplify.LOGGER.error('Failed to update cases in Chronicle.')
                siemplify.LOGGER.exception(e)
            siemplify.LOGGER.info(f'--- Finished Updating Cases in Chronicle ---')

        pending_case_ids = [pending for pending in pending_case_ids if pending.get('id') not in
                            cases_to_remove_from_backlog]
        if pending_case_ids not in [{}, [], None]:
            siemplify.LOGGER.info(f'The following failed case ids were put in the backlog: '
                                  f'{", ".join([str(pending.get("id")) for pending in pending_case_ids])}')
        siemplify.LOGGER.info(f'--- Finished Processing Updated Cases ---')

        siemplify.LOGGER.info(f'--- Start Processing Updated Alerts ---')

        alerts_last_success_timestamp = get_last_success_time_for_job(
            siemplify=siemplify,
            offset_with_metric={"hours": hours_backwards},
            time_format=UNIX_FORMAT,
            timestamp_key=ALERTS_TIMESTAMP_DB_KEY
        )

        pending_alert_ids = read_ids_for_job(siemplify, ALERT_IDS_DB_KEY, default_value_to_return=[])
        siemplify.LOGGER.info(f"Successfully loaded {len(pending_alert_ids)} pending alert ids")

        alerts_count = MAX_FETCH_LIMIT_FOR_JOB - len(pending_alert_ids)
        if alerts_count <= 0:
            if alerts_count < 0:
                siemplify.LOGGER.error(f"Alerts overload: alert limit is {MAX_FETCH_LIMIT_FOR_JOB}. "
                                       f"{abs(alerts_count)} alerts will not be synced")
                pending_alert_ids = pending_alert_ids[:MAX_FETCH_LIMIT_FOR_JOB]
            alerts_metadata = []
        else:
            alerts_metadata = manager.get_updated_alerts_metadata(
                siemplify=siemplify,
                start_timestamp_unix_ms=alerts_last_success_timestamp,
                count=alerts_count,
                allowed_environments=[environment],
                vendor=UNIFIED_CONNECTOR_DEVICE_VENDOR
            )
            siemplify.LOGGER.info(
                'Found {} updated alerts since last fetch time.'.format(len(alerts_metadata)))

        alert_ids = [pending_alert_id.get('group_id') for pending_alert_id in pending_alert_ids]
        alert_ids += [metadata.group_id for metadata in alerts_metadata]
        alert_ids = list(set(alert_ids))
        alerts_with_details = siemplify.get_sync_alerts(alert_ids)

        alerts_cases_with_external_ids = siemplify.get_sync_cases(
            [sync_alert.case_id for sync_alert in alerts_with_details]
        )

        chronicle_alerts = manager.convert_siemplify_alerts_to_chronicle(
            alerts_with_details, alerts_cases_with_external_ids
        )

        successful_alerts = []
        failed_alerts = []
        alerts_to_remove_from_backlog = []

        if alert_ids:
            siemplify.LOGGER.info(f'--- Start Updating Alerts in Chronicle ---')
            siemplify.LOGGER.info(f'Alert ids to be updated: {alert_ids}')
            try:
                updated_chronicle_alerts = manager.batch_update_alerts_in_chronicle(chronicle_alerts)

                for alert in updated_chronicle_alerts:
                    if alert.has_failed:
                        failed_alerts.append(alert)
                    else:
                        successful_alerts.append(alert)

                for failed_alert in failed_alerts:
                    pending_alert = next((item for item in pending_alert_ids if item.get('group_id') ==
                                          failed_alert.group_id), {})
                    retries_counter = pending_alert.get('retries', 0)
                    if retries_counter >= MAX_RETRIES_NUMBER:
                        siemplify.LOGGER.info(f"Max retries reached for alert {failed_alert.group_id}. "
                                              f"Removing from backlog.")
                        alerts_to_remove_from_backlog.append(failed_alert.group_id)
                        continue
                    else:
                        if pending_alert:
                            pending_alert["retries"] += 1
                        else:
                            pending_alert_ids.append({"group_id": failed_alert.group_id, "retries": 1})

                if failed_alerts:
                    siemplify.LOGGER.info(
                        f"The following alerts were not synced: {', '.join([failed.group_id for failed in failed_alerts])}. "
                        f"IDs are put into the backlog.")

                for successful_alert in successful_alerts:
                    ids = [alert.get("group_id") for alert in pending_alert_ids]
                    if successful_alert.group_id in ids:
                        alerts_to_remove_from_backlog.append(successful_alert.group_id)

            except Exception as e:
                siemplify.LOGGER.error('Failed to update alerts in Chronicle.')
                siemplify.LOGGER.exception(e)
            siemplify.LOGGER.info(f'--- Finished Updating Alerts in Chronicle ---')

        pending_alert_ids = [pending for pending in pending_alert_ids if pending.get('group_id') not in
                             alerts_to_remove_from_backlog]
        siemplify.LOGGER.info(f'--- Finished Processing Updated Alerts ---')

        all_cases = sorted(cases_metadata, key=lambda item: item.tracking_time)
        all_alerts = sorted(alerts_metadata, key=lambda item: item.tracking_time)

        siemplify.LOGGER.info("Saving timestamps.")
        if successful_cases + failed_cases and all_cases:
            new_timestamp_for_cases = all_cases[-1].tracking_time
            save_timestamp_for_job(siemplify, new_timestamp=new_timestamp_for_cases, timestamp_key=CASES_TIMESTAMP_DB_KEY)
        if successful_alerts + failed_alerts and all_alerts:
            new_timestamp_for_alerts = all_alerts[-1].tracking_time
            save_timestamp_for_job(siemplify, new_timestamp=new_timestamp_for_alerts, timestamp_key=ALERTS_TIMESTAMP_DB_KEY)

        siemplify.LOGGER.info("Saving pending ids.")
        write_ids_for_job(siemplify, content_to_write=pending_case_ids, db_key=CASE_IDS_DB_KEY)
        write_ids_for_job(siemplify, content_to_write=pending_alert_ids, db_key=ALERT_IDS_DB_KEY)

        siemplify.LOGGER.info('--------------- JOB FINISHED ---------------')

    except Exception as error:
        siemplify.LOGGER.error(f'Got exception on main handler. Error: {error}')
        siemplify.LOGGER.exception(error)
        raise


if __name__ == '__main__':
    main()
