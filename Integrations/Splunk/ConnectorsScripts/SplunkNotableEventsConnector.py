import sys
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyUtils import output_handler, unix_now
from SplunkManager import SplunkManager
from UtilsManager import UNIX_FORMAT, pass_whitelist_filter, string_to_multi_value, is_approaching_timeout
from TIPCommon import extract_connector_param, get_last_success_time, save_timestamp, is_overflowed, read_ids, write_ids
from SiemplifyConnectorsDataModel import AlertInfo
from EnvironmentCommon import GetEnvironmentCommonFactory
from constants import CONNECTOR_NAME, DEFAULT_ALERTS_PROCESS_LIMIT, DEFAULT_TIME_FRAME, ALERT_NAME_SOURCE_MAPPER, \
    SEARCH_NAME_SOURCE

connector_starting_time = unix_now()


@output_handler
def main(is_test_run):
    processed_alerts = []
    siemplify = SiemplifyConnectorExecution()  # Siemplify main SDK wrapper
    siemplify.script_name = CONNECTOR_NAME

    if is_test_run:
        siemplify.LOGGER.info('***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******')

    siemplify.LOGGER.info('------------------- Main - Param Init -------------------')

    server_address = extract_connector_param(siemplify, param_name='Server Address', is_mandatory=True)
    username = extract_connector_param(siemplify, param_name='Username')
    password = extract_connector_param(siemplify, param_name='Password')
    api_token = extract_connector_param(siemplify, param_name='API Token')
    verify_ssl = extract_connector_param(siemplify, param_name='Verify SSL', input_type=bool, is_mandatory=True)
    ca_certificate = extract_connector_param(siemplify, param_name='CA Certificate File', print_value=False)

    environment_field_name = extract_connector_param(siemplify, param_name='Environment Field Name')
    environment_regex_pattern = extract_connector_param(siemplify, param_name='Environment Regex Pattern')

    fetch_limit = extract_connector_param(siemplify, param_name='Max Notable Events To Fetch', input_type=int,
                                          default_value=DEFAULT_ALERTS_PROCESS_LIMIT)
    hours_backwards = extract_connector_param(siemplify, param_name='Fetch Max Hours Backwards', input_type=int,
                                              default_value=DEFAULT_TIME_FRAME)
    lowest_severity = extract_connector_param(siemplify, param_name='Lowest Urgency To Fetch', is_mandatory=True)
    extract_base_events = extract_connector_param(siemplify, param_name='Extract Base Events', print_value=True,
                                                  default_value=True, input_type=bool)
    notable_event_data_along_base_event = extract_connector_param(siemplify,
                                                                  param_name='Notable Event Data Along Base Event',
                                                                  print_value=True, default_value=True, input_type=bool)

    whitelist_as_a_blacklist = extract_connector_param(siemplify, param_name='Use whitelist as a blacklist',
                                                       input_type=bool, is_mandatory=True, print_value=True)

    query_filter = extract_connector_param(siemplify, param_name='Query Filter', print_value=True)

    python_process_timeout = extract_connector_param(siemplify, param_name='PythonProcessTimeout', input_type=int,
                                                     is_mandatory=True, print_value=True)
    multi_value_fields = string_to_multi_value(extract_connector_param(siemplify, param_name='Multivalue Fields',
                                                                       print_value=True))
    alert_name_source = extract_connector_param(siemplify, param_name='Alert Name Source', print_value=True)
    alert_name_source = ALERT_NAME_SOURCE_MAPPER.get(alert_name_source, SEARCH_NAME_SOURCE)
    rule_generator_field_name = extract_connector_param(siemplify, param_name='Rule Generator Field Name')

    try:
        siemplify.LOGGER.info('------------------- Main - Started -------------------')

        # Read already existing alerts ids
        siemplify.LOGGER.info('Reading already existing alerts ids...')
        existing_ids = read_ids(siemplify)

        manager = SplunkManager(server_address=server_address,
                                username=username,
                                password=password,
                                api_token=api_token,
                                ca_certificate=ca_certificate,
                                verify_ssl=verify_ssl,
                                siemplify_logger=siemplify.LOGGER,
                                multi_value_fields=multi_value_fields)
        fetched_alerts = []

        siemplify.LOGGER.info('Fetching notable events...')

        filtered_alerts = manager.get_notable_events(
            existing_ids=existing_ids,
            start_timestamp=int(get_last_success_time(siemplify, offset_with_metric={'hours': hours_backwards},
                                                      time_format=UNIX_FORMAT) / 1000),
            severity=lowest_severity, query_filter=query_filter, limit=fetch_limit)

        siemplify.LOGGER.info('Fetched {} notable events'.format(len(filtered_alerts)))

        if is_test_run:
            siemplify.LOGGER.info('This is a TEST run. Only 1 alert will be processed.')
            filtered_alerts = filtered_alerts[:1]

        for alert in filtered_alerts:
            try:
                if len(processed_alerts) >= fetch_limit:
                    # Provide slicing for the alerts.
                    siemplify.LOGGER.info(
                        'Reached max number of alerts cycle. No more alerts will be processed in this cycle.'
                    )
                    break

                siemplify.LOGGER.info(f'\n Started processing Alert {alert.event_id} - {alert.search_name}. '
                                      f'Timestamp is {alert.timestamp}')

                if is_approaching_timeout(connector_starting_time, python_process_timeout):
                    siemplify.LOGGER.info('Timeout is approaching. Connector will gracefully exit')
                    break

                # Update existing alerts
                existing_ids.append(alert.event_id)
                fetched_alerts.append(alert)

                if not pass_whitelist_filter(siemplify, whitelist_as_a_blacklist, model=alert, model_key='search_name'):
                    siemplify.LOGGER.info(f'Alert {alert.event_id} did not pass filters skipping....')
                    continue

                alert_info = alert.get_alert_info(
                    AlertInfo(),
                    GetEnvironmentCommonFactory.create_environment_manager(
                        siemplify,
                        environment_field_name,
                        environment_regex_pattern
                    ),
                    alert_name_source,
                    rule_generator_field_name
                )
                alert_info.events = manager.get_events(alert, extract_base_events, notable_event_data_along_base_event)

                if is_overflowed(siemplify, alert_info, is_test_run):
                    siemplify.LOGGER.info(
                        '{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping.'
                            .format(alert_name=str(alert_info.rule_generator),
                                    alert_identifier=str(alert_info.ticket_id),
                                    environment=str(alert_info.environment),
                                    product=str(alert_info.device_product)))
                    # If is overflowed we should skip
                    continue
                processed_alerts.append(alert_info)
                siemplify.LOGGER.info(f'Alert {alert.event_id} was created.')

            except Exception as e:
                siemplify.LOGGER.error(f'Failed to process alert {alert.event_id}')
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            siemplify.LOGGER.info(f'\n Finished processing alert {alert.event_id}')

        if not is_test_run:
            save_timestamp(siemplify, alerts=fetched_alerts, convert_timestamp_to_micro_time=True)
            write_ids(siemplify, existing_ids)

    except Exception as err:
        siemplify.LOGGER.error(f'Got exception on main handler. Error: {err}')
        siemplify.LOGGER.exception(err)
        if is_test_run:
            raise

    siemplify.LOGGER.info(f'Created total of {len(processed_alerts)} cases')
    siemplify.LOGGER.info('------------------- Main - Finished -------------------')
    siemplify.return_package(processed_alerts)


if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test)
