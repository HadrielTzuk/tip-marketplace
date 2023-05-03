import sys
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyUtils import output_handler, utc_now, convert_datetime_to_unix_time, unix_now, convert_unixtime_to_datetime
from FireEyeCMManager import FireEyeCMManager
from EnvironmentCommon import GetEnvironmentCommonFactory

from TIPCommon import (
    extract_connector_param,
    read_ids,
    write_ids,
    is_overflowed,
    is_approaching_timeout,
    validate_timestamp
)
from datetime import timedelta

from FireEyeCMConstants import (
    ALERTS_CONNECTOR_NAME,
    DEFAULT_TIME_FRAME,
    ACCEPTABLE_TIME_INTERVAL_IN_MINUTES,
    WHITELIST_FILTER,
    BLACKLIST_FILTER,
    DURATION
)

connector_starting_time = unix_now()


@output_handler
def main(is_test_run):
    processed_alerts = []
    siemplify = SiemplifyConnectorExecution()  # Siemplify main SDK wrapper
    siemplify.script_name = ALERTS_CONNECTOR_NAME

    if is_test_run:
        siemplify.LOGGER.info('***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******')

    siemplify.LOGGER.info('------------------- Main - Param Init -------------------')

    api_root = extract_connector_param(siemplify, param_name='API Root', is_mandatory=True)
    username = extract_connector_param(siemplify, param_name='Username', is_mandatory=True)
    password = extract_connector_param(siemplify, param_name='Password', is_mandatory=True)
    verify_ssl = extract_connector_param(siemplify, param_name='Verify SSL', default_value=True, input_type=bool,
                                         is_mandatory=True)
    environment_field_name = extract_connector_param(siemplify, param_name='Environment Field Name', default_value='')
    environment_regex_pattern = extract_connector_param(siemplify, param_name='Environment Regex Pattern',
                                                        default_value='.*')
    hours_backwards = extract_connector_param(siemplify, param_name='Fetch Max Hours Backwards',
                                              input_type=int, default_value=DEFAULT_TIME_FRAME)

    whitelist_as_a_blacklist = extract_connector_param(siemplify, 'Use whitelist as a blacklist',
                                                       is_mandatory=True, input_type=bool, print_value=True)

    whitelist_filter_type = BLACKLIST_FILTER if whitelist_as_a_blacklist else WHITELIST_FILTER

    whitelist = siemplify.whitelist

    python_process_timeout = extract_connector_param(siemplify, param_name="PythonProcessTimeout", input_type=int,
                                                     is_mandatory=True, print_value=True)

    try:
        siemplify.LOGGER.info('------------------- Main - Started -------------------')

        # Read already existing alerts ids
        siemplify.LOGGER.info('Reading already existing alerts ids...')
        existing_ids = read_ids(siemplify)

        siemplify.LOGGER.info('Fetching alerts...')
        manager = FireEyeCMManager(
            api_root=api_root,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            siemplify=siemplify
        )

        if is_test_run:
            siemplify.LOGGER.info('This is a test run. Ignoring stored timestamps')
            last_success_time_datetime = validate_timestamp(
                utc_now() - timedelta(hours=hours_backwards), hours_backwards
            )
        else:
            last_success_time_datetime = validate_timestamp(
                siemplify.fetch_timestamp(datetime_format=True), hours_backwards
            )

        fetched_alerts = []
        filtered_alerts = manager.get_alerts(
            existing_ids=existing_ids,
            start_time=last_success_time_datetime,
            duration=DURATION
        )

        siemplify.LOGGER.info('Fetched {} alerts'.format(len(filtered_alerts)))

        if is_test_run:
            siemplify.LOGGER.info('This is a TEST run. Only 1 alert will be processed.')
            filtered_alerts = filtered_alerts[:1]

        for alert in filtered_alerts:
            try:
                siemplify.LOGGER.info('Started processing Alert {} - {}'.format(alert.uuid, alert.name),
                                      alert_id=alert.uuid)

                if is_approaching_timeout(connector_starting_time, python_process_timeout):
                    siemplify.LOGGER.info('Timeout is approaching. Connector will gracefully exit')
                    break

                if not pass_time_filter(siemplify, alert):
                    siemplify.LOGGER.info(
                        'Alerts which are older then {} minutes fetched. Stopping connector....'.format(
                            ACCEPTABLE_TIME_INTERVAL_IN_MINUTES))
                    break

                # Update existing alerts
                existing_ids.append(alert.uuid)
                fetched_alerts.append(alert)

                if not pass_whitelist_filter(siemplify, alert, whitelist, whitelist_filter_type):
                    siemplify.LOGGER.info('Alert {} did not pass filters skipping....'.format(alert.uuid))
                    continue

                common_environment = GetEnvironmentCommonFactory.create_environment_manager(
                    siemplify=siemplify,
                    environment_field_name=environment_field_name,
                    environment_regex_pattern=environment_regex_pattern
                )

                alert_info = alert.to_alert_info(common_environment)

                if is_overflowed(siemplify, alert_info, is_test_run):
                    siemplify.LOGGER.info(
                        '{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping.'
                            .format(alert_name=alert_info.rule_generator,
                                    alert_identifier=alert_info.ticket_id,
                                    environment=alert_info.environment,
                                    product=alert_info.device_product))
                    # If is overflowed we should skip
                    continue

                processed_alerts.append(alert_info)
                siemplify.LOGGER.info('Alert {} was created.'.format(alert.uuid))

            except Exception as e:
                siemplify.LOGGER.error('Failed to process alert {}'.format(alert.uuid), alert_id=alert.uuid)
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            siemplify.LOGGER.info('Finished processing Alert {}'.format(alert.uuid), alert_id=alert.uuid)

        if not is_test_run:
            if fetched_alerts:
                new_timestamp = fetched_alerts[-1].occurred_time_unix
                siemplify.save_timestamp(new_timestamp=new_timestamp)
                siemplify.LOGGER.info(
                    'New timestamp {} has been saved'.format(convert_unixtime_to_datetime(new_timestamp).isoformat())
                )

            write_ids(siemplify, existing_ids)

    except Exception as err:
        siemplify.LOGGER.error('Got exception on main handler. Error: {0}'.format(err))
        siemplify.LOGGER.exception(err)
        if is_test_run:
            raise

    siemplify.LOGGER.info('Created total of {} cases'.format(len(processed_alerts)))
    siemplify.LOGGER.info('------------------- Main - Finished -------------------')
    siemplify.return_package(processed_alerts)


def pass_time_filter(siemplify, alert):
    # time filter
    time_passed_from_first_detected_in_minutes = (unix_now() - alert.occurred_time_unix) / 60000
    if time_passed_from_first_detected_in_minutes <= ACCEPTABLE_TIME_INTERVAL_IN_MINUTES:
        siemplify.LOGGER.info('Alert did not pass time filter. Detected approximately {} minutes ago.'.format(
            time_passed_from_first_detected_in_minutes))
        return False
    return True


def pass_whitelist_filter(siemplify, alert, whitelist, whitelist_filter_type):
    # whitelist filter
    if whitelist:
        if whitelist_filter_type == BLACKLIST_FILTER and alert.name in whitelist:
            siemplify.LOGGER.info("Alert with name: {} did not pass blacklist filter.".format(alert.name))
            return False

        if whitelist_filter_type == WHITELIST_FILTER and alert.name not in whitelist:
            siemplify.LOGGER.info("Alert with name: {} did not pass whitelist filter.".format(alert.name))
            return False

    return True


if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test)
