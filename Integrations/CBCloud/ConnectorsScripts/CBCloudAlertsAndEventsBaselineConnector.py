import sys
import arrow
from CBCloudManager import CBCloudManager
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyUtils import output_handler, unix_now

from exceptions import CBCloudException
from TIPCommon import extract_connector_param, is_overflowed, get_last_success_time, save_timestamp, string_to_multi_value
from EnvironmentCommon import GetEnvironmentCommonFactory
from constants import BASELINE_CONNECTOR_NAME, WHITELIST_FILTER, BLACKLIST_FILTER, MAP_FILE, BACKLOG_FILE, \
    DEFAULT_ALERT_FIELD_FOR_RULE_NAME, DEFAULT_ALERT_FIELD_FOR_RULE_GENERATOR, DEFAULT_ALERT_REPUTATION_TO_INGEST, \
    DEFAULT_MAX_ALERTS_PER_CYCLE, DEFAULT_EVENTS_LIMIT_TO_INGEST_PER_ALERT, PROVIDER_NAME, DEFAULT_VENDOR, \
    SIEMPLIFY_ALERT_NAME, SIEMPLIFY_RULE_GENERATOR, OFFENSE_EVENTS_FILE, KEY_FOR_SAVED_ALERTS, \
    DEFAULT_MAX_BACKLOG_ALERTS_PER_CYCLE, KEY_FOR_SAVED_ALERTS_TIME, OFFENSE_EVENTS_DB_KEY
from utils import TIMEOUT_THRESHOLD, is_approaching_timeout, validate_alert_name_field_name, \
    validate_rule_generator_field_name, add_alert_to_backlog, add_events_to_alert_info, \
    remove_backlog_alert, backlog_ids_exists, read_offense_events, read_backlog_ids, remove_backlog_alert_by_id, \
    save_backlog_ids, save_alerts, pass_filters

EMPTY_ALERTS_JSON_FILE = {KEY_FOR_SAVED_ALERTS: {}}
DEFAULT_OFFSET_TIME_HOURS = 24
MAX_ENRICHED_EVENTS_PER_REQUEST = 10
CONNECTOR_STARTING_TIME = unix_now()

def is_alert_already_seen(alert, existing_alerts):
    return bool(existing_alerts.get(alert.id_with_legacy_id))

def get_events(siemplify, alert, manager, max_events_per_alert,
               python_process_timeout):
    event_details = []
    processed_event_ids = []
    all_event_ids = [event.id for event in manager.get_events_by_alert_id(
        alert_id=alert.legacy_alert_id,
        max_events_to_return=max_events_per_alert
    )]
    siemplify.LOGGER.info(
        f'Successfully received "{len(all_event_ids)}" new events for alert "{alert.id_for_logging}"')

    for event_ids in [all_event_ids[x:x + MAX_ENRICHED_EVENTS_PER_REQUEST] for x in
                      range(0, len(all_event_ids), MAX_ENRICHED_EVENTS_PER_REQUEST)]:
        if is_approaching_timeout(python_process_timeout, CONNECTOR_STARTING_TIME, TIMEOUT_THRESHOLD):
            siemplify.LOGGER.info('Timeout is approaching. Connector will gracefully exit.')
            break
        event_details.extend(manager.get_events_detailed_information(event_ids=event_ids))
        processed_event_ids.extend(event_ids)
    return processed_event_ids, event_details


def attach_events_to_alert_info(siemplify, alert, alert_info, manager, max_events_per_alert, python_process_timeout):
    event_ids = []
    is_attached = True
    try:
        if not alert.has_events:
            siemplify.LOGGER.info(f'Alert of type {alert.type} with no additional events.')
            alert_info = add_events_to_alert_info(alert_info, [alert], alert.id_for_logging)
            event_ids = [alert.id]
        else:
            event_ids, events_details = get_events(siemplify, alert, manager, max_events_per_alert,
                                                   python_process_timeout)
            siemplify.LOGGER.info(f'Successfully loaded "{len(event_ids)}" events for alert')
            alert_info = add_events_to_alert_info(alert_info, events_details, alert.id_for_logging)
    except CBCloudException as e:
        siemplify.LOGGER.info(e)
        is_attached = False
    except Exception as e:
        siemplify.LOGGER.error(f'Failed to load events for alert "{alert.id_for_logging}"')
        siemplify.LOGGER.exception(e)
        is_attached = False
    return alert_info, event_ids, is_attached


def finish_alert_processing(siemplify, alert_info, alert, processed_alerts, processed_alert_ids):
    processed_alerts.append(alert_info)
    processed_alert_ids.append(alert.id_with_legacy_id)
    siemplify.LOGGER.info(f'Cases for alert "{alert.id_for_logging}" was created.')
    return processed_alerts, processed_alert_ids


def process_backlog_alerts(siemplify,
                           manager,
                           backlog_ids_to_process,
                           max_backlog_alerts,
                           environment_common,
                           alert_name_field_name,
                           rule_generator_field_name,
                           events_limit_to_ingest_per_alert,
                           python_process_timeout,
                           processed_alerts,
                           processed_alert_ids,
                           alert_name_template=None,
                           rule_generator_template=None
                           ):
    siemplify.LOGGER.info('Processing backlog alerts')
    backlog_alerts = manager.get_alerts_by_id(list(backlog_ids_to_process.keys()), max_backlog_alerts)
    siemplify.LOGGER.info(f'Loaded {len(backlog_alerts)} backlog alerts')
    for backlog_alert in backlog_alerts:
        alert_info_without_events = backlog_alert.to_alert_info(
            environment_common, alert_name_field_name, rule_generator_field_name,
            alert_name_template=alert_name_template, rule_generator_template=rule_generator_template
        )

        alert_info, event_ids, is_attached = attach_events_to_alert_info(
            siemplify=siemplify,
            alert=backlog_alert,
            alert_info=alert_info_without_events,
            manager=manager,
            max_events_per_alert=events_limit_to_ingest_per_alert,
            python_process_timeout=python_process_timeout)

        if not alert_info or not is_attached:
            siemplify.LOGGER.info(f'Failed to process backlog alert {backlog_alert.id_for_logging}.')
            continue

        backlog_ids_to_process = remove_backlog_alert(siemplify, backlog_ids_to_process, backlog_alert)
        siemplify.LOGGER.info(f'Backlog alert {backlog_alert.id_for_logging} processed successfully.')

        processed_alerts, processed_alert_ids = finish_alert_processing(siemplify, alert_info, backlog_alert,
                                                                        processed_alerts, processed_alert_ids)
    return processed_alerts, processed_alert_ids, backlog_ids_to_process


def save_alert_json(siemplify, alert, offense_events):
    """
    Save new alert to the offense_events.json file
    :param siemplify: {Alert} Siemplify instance
    :param alert: {Alert} The alert to save
    :param offense_events: Offense events
    """
    # If alert does not exist in offense_events.json file - add new alert to file
    if alert.id_with_legacy_id not in offense_events[KEY_FOR_SAVED_ALERTS].keys():
        siemplify.LOGGER.info("Alert {} was not found in offense.json file. Creating new record".format(
            alert.id_with_legacy_id
        ))
        # Offense was never in the offense events file. Need to create new record
        offense_events[KEY_FOR_SAVED_ALERTS][alert.id_with_legacy_id] = {
            "last_seen_time": unix_now(),
        }


@output_handler
def main(is_test_run):
    processed_alerts = []
    processed_alert_ids = []
    all_alerts = []
    alerts_from_api = []
    new_backlog_alerts = []
    should_process_backlog_alerts = True
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = BASELINE_CONNECTOR_NAME

    if is_test_run:
        siemplify.LOGGER.info('***** This is an \'IDE Play Button\' \'Run Connector once\' test run ******')

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    environment_field_name = extract_connector_param(
        siemplify,
        param_name='Environment Field Name',
        print_value=True
    )

    environment_regex_pattern = extract_connector_param(
        siemplify,
        param_name='Environment Regex Pattern',
        print_value=True
    )

    python_process_timeout = extract_connector_param(
        siemplify,
        param_name="PythonProcessTimeout",
        input_type=int,
        is_mandatory=True,
        print_value=True
    )

    api_root = extract_connector_param(
        siemplify,
        param_name='API Root',
        is_mandatory=True,
        print_value=True
    )

    org_key = extract_connector_param(
        siemplify,
        param_name='Organization Key',
        is_mandatory=True,
        print_value=True
    )

    api_id = extract_connector_param(
        siemplify,
        param_name='API ID',
        is_mandatory=True
    )

    api_secret_key = extract_connector_param(
        siemplify,
        param_name='API Secret Key',
        is_mandatory=True
    )

    verify_ssl = extract_connector_param(
        siemplify,
        param_name='Verify SSL',
        input_type=bool,
        print_value=True
    )

    offset_time_in_hours = extract_connector_param(
        siemplify,
        param_name='Offset Time In Hours',
        input_type=int,
        is_mandatory=True,
        print_value=True,
        default_value=DEFAULT_OFFSET_TIME_HOURS
    )

    max_alerts_per_cycle = extract_connector_param(
        siemplify,
        param_name='Max Alerts Per Cycle',
        input_type=int,
        is_mandatory=True,
        print_value=True,
        default_value=DEFAULT_MAX_ALERTS_PER_CYCLE
    )

    min_severity = extract_connector_param(
        siemplify,
        param_name='Minimum Severity to Fetch',
        print_value=True
    )

    alert_name_field_name = extract_connector_param(
        siemplify,
        param_name='What Alert Field to use for Name field',
        is_mandatory=True,
        print_value=True,
        default_value=DEFAULT_ALERT_FIELD_FOR_RULE_NAME
    )

    rule_generator_field_name = extract_connector_param(
        siemplify,
        param_name='What Alert Field to use for Rule Generator',
        is_mandatory=True,
        print_value=True,
        default_value=DEFAULT_ALERT_FIELD_FOR_RULE_GENERATOR
    )

    alert_reputations_to_ingest = extract_connector_param(
        siemplify,
        param_name='Alert Reputation to Ingest',
        is_mandatory=True,
        default_value=DEFAULT_ALERT_REPUTATION_TO_INGEST,
        print_value=True
    )

    events_limit_to_ingest_per_alert = extract_connector_param(
        siemplify,
        param_name='Events Limit to Ingest per Alert',
        is_mandatory=True,
        default_value=DEFAULT_EVENTS_LIMIT_TO_INGEST_PER_ALERT,
        input_type=int,
        print_value=True
    )

    watchlist_name_filter = string_to_multi_value(extract_connector_param(
        siemplify,
        param_name='Watchlist Name Filter',
        print_value=True
    ))

    alerts_backlog_timer = extract_connector_param(
        siemplify,
        param_name='Alerts Backlog Timer',
        input_type=int,
        print_value=True
    )

    max_backlog_alerts = extract_connector_param(
        siemplify,
        param_name='Max Backlog Alerts per Cycle',
        input_type=int,
        print_value=True,
        default_value=DEFAULT_MAX_BACKLOG_ALERTS_PER_CYCLE
    )

    whitelist_as_a_blacklist = extract_connector_param(
        siemplify,
        param_name='Use whitelist as a blacklist',
        is_mandatory=True,
        input_type=bool,
        print_value=True
    )

    alert_name_template = extract_connector_param(
        siemplify,
        param_name='Alert Name Template',
        print_value=True
    )

    rule_generator_template = extract_connector_param(
        siemplify,
        param_name='Rule Generator Template',
        print_value=True
    )

    siemplify.LOGGER.info('------------------- Main - Started -------------------')

    whitelist_filter_type = BLACKLIST_FILTER if whitelist_as_a_blacklist else WHITELIST_FILTER
    whitelist = siemplify.whitelist if isinstance(siemplify.whitelist, list) else [siemplify.whitelist]

    try:
        validate_alert_name_field_name(alert_name_field_name)
        validate_rule_generator_field_name(rule_generator_field_name)

        environment_common = GetEnvironmentCommonFactory.create_environment_manager(siemplify, environment_field_name,
                                                                                    environment_regex_pattern,MAP_FILE)

        last_success_time = get_last_success_time(siemplify, offset_with_metric={'hours': offset_time_in_hours})

        manager = CBCloudManager(api_root=api_root, org_key=org_key, api_id=api_id, api_secret_key=api_secret_key,
                                 verify_ssl=verify_ssl, logger=siemplify.LOGGER)

        alerts_from_api = manager.get_alerts(
            start_time=last_success_time.isoformat(),
            end_time=arrow.utcnow().isoformat(),
            min_severity=min_severity,
            sort_order="ASC",
            workflows=["OPEN"],
            sort_by="create_time",
            limit=max_alerts_per_cycle,
            categories=whitelist if whitelist_filter_type == WHITELIST_FILTER else None,
        )
        alerts_from_api = sorted(alerts_from_api, key=lambda alert: alert.create_time_ms)
        siemplify.LOGGER.info(
            'Fetched alerts {}'.format(', '.join([alert.id_for_logging for alert in alerts_from_api])))

        siemplify.LOGGER.info('Reading already existing alerts...')

        existing_alerts = read_offense_events(siemplify, EMPTY_ALERTS_JSON_FILE.get(KEY_FOR_SAVED_ALERTS))

        siemplify.LOGGER.info(f'fetched already existing alerts:\n{existing_alerts}')

        alert_legacy_ids = []
        for alert in alerts_from_api:
            try:
                if is_approaching_timeout(python_process_timeout, CONNECTOR_STARTING_TIME, TIMEOUT_THRESHOLD):
                    siemplify.LOGGER.info('Timeout is approaching. Connector will gracefully exit')
                    break
                if len(processed_alerts) >= max_alerts_per_cycle:
                    siemplify.LOGGER.info(f'Maximum alerts count ({max_alerts_per_cycle}) reached! Stopping '
                                          f'processing alerts')
                    break
                if is_test_run and processed_alerts:
                    siemplify.LOGGER.info('Maximum alerts count (1) for test run reached!')
                    break
                siemplify.LOGGER.info(f'Starting alert with id: {alert.id_for_logging}')
                all_alerts.append(alert)

                # Check if already processed
                if is_alert_already_seen(alert, existing_alerts):
                    siemplify.LOGGER.info(f'Alert "{alert.id_for_logging}" already processed. Skipping...')
                    continue
                # Check if alert passes filters
                if not pass_filters(siemplify, alert, alert_reputations_to_ingest, whitelist_filter_type, whitelist,
                                    watchlist_name_filter):
                    continue
                siemplify.LOGGER.info(f'Processing alert with id: {alert.id_for_logging}')

                alert_info_without_events = alert.to_alert_info(
                    environment_common, alert_name_field_name, rule_generator_field_name,
                    alert_name_template=alert_name_template, rule_generator_template=rule_generator_template
                )

                if is_overflowed(siemplify, alert_info_without_events, is_test_run):
                    siemplify.LOGGER.info(
                        '{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping.'
                            .format(alert_name=alert_info_without_events.rule_generator,
                                    alert_identifier=alert_info_without_events.ticket_id,
                                    environment=alert_info_without_events.environment,
                                    product=alert_info_without_events.device_product))
                    # If is overflowed we should skip
                    continue

                alert_info, event_ids, is_attached = attach_events_to_alert_info(
                    siemplify=siemplify,
                    alert=alert,
                    alert_info=alert_info_without_events,
                    manager=manager,
                    max_events_per_alert=events_limit_to_ingest_per_alert,
                    python_process_timeout=python_process_timeout)
                if not alert_info or not is_attached:
                    new_backlog_alerts = add_alert_to_backlog(siemplify, new_backlog_alerts, alert)
                    continue

                processed_alerts, processed_alert_ids = finish_alert_processing(siemplify, alert_info, alert,
                                                                                processed_alerts, processed_alert_ids)
                alert_legacy_ids.append(alert.legacy_alert_id)

            except Exception as e:
                siemplify.LOGGER.error(f'Failed to process alert with id {alert.id_for_logging}')
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

        # Backlog alerts
        backlog_ids_to_process, total_backlog_ids = read_backlog_ids(siemplify, alerts_backlog_timer)
        is_backlog_empty = not bool(backlog_ids_exists(backlog_ids_to_process))

        backlog_alerts_to_remove = {_id: value for _id, value in backlog_ids_to_process.items() if
                                    _id in alert_legacy_ids}
        for key, value in backlog_alerts_to_remove.items():
            siemplify.LOGGER.info(
                "Alert with ID: {} was already processed and will be removed from backlog.".format(key))
            remove_backlog_alert_by_id(siemplify, backlog_ids_to_process, key)

        if is_backlog_empty or is_approaching_timeout(python_process_timeout, CONNECTOR_STARTING_TIME,
                                                      TIMEOUT_THRESHOLD):
            siemplify.LOGGER.info('No backlog id to process.') if is_backlog_empty else \
                siemplify.LOGGER.info('Timeout is approaching. Backlog alerts will not be processed.')

            should_process_backlog_alerts = False

        if should_process_backlog_alerts:
            processed_alerts, processed_alert_ids, backlog_ids_to_process = process_backlog_alerts(
                siemplify,
                manager,
                backlog_ids_to_process,
                max_backlog_alerts,
                environment_common,
                alert_name_field_name,
                rule_generator_field_name,
                events_limit_to_ingest_per_alert,
                python_process_timeout,
                processed_alerts,
                processed_alert_ids,
                alert_name_template=alert_name_template,
                rule_generator_template=rule_generator_template
            )

        if not is_test_run:
            save_backlog_ids(siemplify, backlog_ids_to_process, new_backlog_alerts)

            if processed_alert_ids:
                save_alerts(siemplify, existing_alerts, processed_alert_ids,
                            offset_time_in_hours, EMPTY_ALERTS_JSON_FILE)
            if all_alerts:
                save_timestamp(siemplify, alerts=all_alerts, timestamp_key='create_time_ms')

    except Exception as e:
        siemplify.LOGGER.error(f'General error: {e}')
        siemplify.LOGGER.exception(e)

        if is_test_run:
            raise

    siemplify.LOGGER.info(
        f'Alert processed: {len(all_alerts)} out of {len(alerts_from_api)}')
    siemplify.LOGGER.info(f'Created total of {len(processed_alerts)} cases')

    siemplify.LOGGER.info('------------------- Main - Finished -------------------')
    siemplify.return_package(processed_alerts)


if __name__ == '__main__':
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test)
