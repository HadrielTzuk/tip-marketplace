import sys

from EnvironmentCommon import GetEnvironmentCommonFactory
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import output_handler, utc_now, convert_datetime_to_unix_time, unix_now
from TIPCommon import (
    extract_connector_param,
    get_last_success_time,
    read_ids,
    write_ids,
    UNIX_FORMAT,
    is_overflowed,
    save_timestamp,
    is_approaching_timeout
)
from VectraManager import VectraManager
from constants import (
    CONNECTOR_NAME,
    DEFAULT_TIME_FRAME,
    ACCEPTABLE_TIME_INTERVAL_IN_MINUTES,
    WHITELIST_FILTER,
    BLACKLIST_FILTER,
    DETECTION_CATEGORIES,
    MAX_IDS
)

connector_starting_time = unix_now()


@output_handler
def main(is_test_run):
    processed_alerts = []
    siemplify = SiemplifyConnectorExecution()  # Siemplify main SDK wrapper
    siemplify.script_name = CONNECTOR_NAME

    if is_test_run:
        siemplify.LOGGER.info(u'***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******')

    siemplify.LOGGER.info(u'------------------- Main - Param Init -------------------')

    api_root = extract_connector_param(siemplify, param_name=u'API Root', input_type=unicode, is_mandatory=True)
    api_token = extract_connector_param(siemplify, param_name=u'API Token', input_type=unicode, is_mandatory=True)
    verify_ssl = extract_connector_param(siemplify, param_name=u'Verify SSL', default_value=True, input_type=bool,
                                         is_mandatory=True)
    environment_field_name = extract_connector_param(siemplify, param_name=u'Environment Field Name', default_value=u'',
                                                     input_type=unicode)
    environment_regex_pattern = extract_connector_param(siemplify, param_name=u'Environment Regex Pattern',
                                                        input_type=unicode)

    fetch_limit = extract_connector_param(siemplify, param_name=u'Max Detections To Fetch', input_type=int)
    hours_backwards = extract_connector_param(siemplify, param_name=u'Fetch Max Hours Backwards',
                                              input_type=int, default_value=DEFAULT_TIME_FRAME)

    lowest_certainty = extract_connector_param(siemplify, param_name=u'Lowest Certainty Score To Fetch', input_type=int,
                                               default_value=0)
    lowest_threat_score = extract_connector_param(siemplify, param_name=u'Lowest Threat Score To Fetch', input_type=int,
                                                  is_mandatory=True)
    category_filter = extract_connector_param(siemplify, param_name=u'Category Filter',
                                              default_value=u','.join(DETECTION_CATEGORIES), input_type=unicode)

    whitelist_as_a_blacklist = extract_connector_param(siemplify, u'Use whitelist as a blacklist', input_type=bool,
                                                       is_mandatory=True, print_value=True)
    whitelist_filter_type = BLACKLIST_FILTER if whitelist_as_a_blacklist else WHITELIST_FILTER

    whitelist = siemplify.whitelist

    python_process_timeout = extract_connector_param(siemplify, param_name=u"PythonProcessTimeout", input_type=int,
                                                     is_mandatory=True, print_value=True)

    device_product_field = extract_connector_param(siemplify, "DeviceProductField", is_mandatory=True)

    try:
        siemplify.LOGGER.info(u'------------------- Main - Started -------------------')

        # Read already existing alerts ids
        siemplify.LOGGER.info(u'Reading already existing alerts ids...')
        existing_ids = read_ids(siemplify)

        siemplify.LOGGER.info(u'Fetching threats...')
        manager = VectraManager(api_root, api_token, verify_ssl, siemplify)

        fetched_alerts = []
        filtered_alerts = manager.get_detections(
            existing_ids=existing_ids,
            limit=fetch_limit,
            start_timestamp=get_last_success_time(siemplify=siemplify,
                                                  offset_with_metric={u'hours': hours_backwards},
                                                  time_format=UNIX_FORMAT),
            threat_score=lowest_threat_score,
            certainty_score=lowest_certainty,
            categories=category_filter)

        siemplify.LOGGER.info(u'Fetched {} threats'.format(len(filtered_alerts)))

        if is_test_run:
            siemplify.LOGGER.info(u'This is a TEST run. Only 1 alert will be processed.')
            filtered_alerts = filtered_alerts[:1]

        for alert in filtered_alerts:
            try:
                if len(processed_alerts) >= fetch_limit:
                    # Provide slicing for the alarms amount.
                    siemplify.LOGGER.info(
                        u'Reached max number of alerts cycle. No more alerts will be processed in this cycle.'
                    )
                    break

                siemplify.LOGGER.info(u'Started processing Alert {} - {} '.format(alert.detection_id, alert.detection_type), alert_id=alert.detection_id)

                if is_approaching_timeout(connector_starting_time, python_process_timeout):
                    siemplify.LOGGER.info(u'Timeout is approaching. Connector will gracefully exit')
                    break

                if not pass_time_filter(siemplify, alert):
                    siemplify.LOGGER.info(
                        u'Alerts which are older then {} minutes fetched. Stopping connector....'.format(
                            ACCEPTABLE_TIME_INTERVAL_IN_MINUTES))
                    break

                # Update existing alerts
                existing_ids.append(alert.detection_id)
                fetched_alerts.append(alert)

                if not pass_whitelist_filter(siemplify, alert, whitelist, whitelist_filter_type):
                    siemplify.LOGGER.info(u'Alert {} did not pass filters skipping....'.format(alert.detection_id))
                    continue

                environment_common = GetEnvironmentCommonFactory.create_environment_manager(
                        siemplify,
                        environment_field_name,
                        environment_regex_pattern
                    )
                alert_info = alert.get_alert_info(
                    AlertInfo(),
                    environment_common,
                    device_product_field
                )

                if is_overflowed(siemplify, alert_info, is_test_run):
                    siemplify.LOGGER.info(
                        u'{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping.'
                        .format(alert_name=unicode(alert_info.rule_generator),
                                alert_identifier=unicode(alert_info.ticket_id),
                                environment=unicode(alert_info.environment),
                                product=unicode(alert_info.device_product)))
                    # If is overflowed we should skip
                    continue

                processed_alerts.append(alert_info)
                siemplify.LOGGER.info(u'Alert {} was created.'.format(alert.detection_id))

            except Exception as e:
                siemplify.LOGGER.error(u'Failed to process alert {}'.format(alert.detection_id), alert_id=alert.detection_id)
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            siemplify.LOGGER.info(u'Finished processing Alert {}'.format(alert.detection_id), alert_id=alert.detection_id)

        if not is_test_run:
            save_timestamp(siemplify=siemplify, alerts=fetched_alerts)
            write_ids(siemplify, existing_ids, stored_ids_limit=MAX_IDS)

    except Exception as err:
        siemplify.LOGGER.error(u'Got exception on main handler. Error: {0}'.format(err))
        siemplify.LOGGER.exception(err)
        if is_test_run:
            raise

    siemplify.LOGGER.info(u'Created total of {} cases'.format(len(processed_alerts)))
    siemplify.LOGGER.info(u'------------------- Main - Finished -------------------')
    siemplify.return_package(processed_alerts)


def pass_time_filter(siemplify, alert):
    # time filter
    time_passed_from_first_detected_in_minutes = (convert_datetime_to_unix_time(
        utc_now()) - alert.first_timestamp) / 60000
    if time_passed_from_first_detected_in_minutes <= ACCEPTABLE_TIME_INTERVAL_IN_MINUTES:
        siemplify.LOGGER.info(u'Alert did not pass time filter. Detected approximately {} minutes ago.'.format(
            unicode(time_passed_from_first_detected_in_minutes)))
        return False
    return True


def pass_whitelist_filter(siemplify, alert, whitelist, whitelist_filter_type):
    # whitelist filter
    if whitelist:
        if whitelist_filter_type == BLACKLIST_FILTER and alert.detection_type in whitelist:
            siemplify.LOGGER.info(u"Threat with name: {} did not pass blacklist filter.".format(alert.detection_type))
            return False

        if whitelist_filter_type == WHITELIST_FILTER and alert.detection_type not in whitelist:
            siemplify.LOGGER.info(u"Threat with name: {} did not pass whitelist filter.".format(alert.detection_type))
            return False

    return True


if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == u'True')
    main(is_test)
