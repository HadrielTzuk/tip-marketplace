import sys
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyUtils import output_handler, unix_now
from McAfeeMvisionEPOV2Manager import McAfeeMvisionEPOV2Manager
from UtilsManager import get_environment_common, get_last_success_time, is_overflowed, save_timestamp, \
    read_ids, write_ids, is_approaching_timeout
from TIPCommon import extract_connector_param
from constants import DEFAULT_SCOPES


# =====================================
#             CONSTANTS               #
# =====================================
CONNECTOR_NAME = 'McAfee Mvision EPO V2 - Events Connector'
HOURS_LIMIT_IN_IDS_FILE = 72
TIMEOUT_THRESHOLD = 0.9


@output_handler
def main(is_test_run):
    connector_starting_time = unix_now()
    all_alerts = []
    processed_alerts = []
    siemplify = SiemplifyConnectorExecution()  # Siemplify main SDK wrapper
    siemplify.script_name = CONNECTOR_NAME

    if is_test_run:
        siemplify.LOGGER.info('***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******')

    siemplify.LOGGER.info('------------------- Main - Param Init -------------------')

    api_root = extract_connector_param(siemplify, param_name='API Root', is_mandatory=True)
    iam_root = extract_connector_param(siemplify, param_name='IAM Root', is_mandatory=True)
    client_id = extract_connector_param(siemplify, param_name='Client ID', is_mandatory=True)
    client_secret = extract_connector_param(siemplify, param_name='Client Secret', is_mandatory=True)
    api_key = extract_connector_param(siemplify, param_name='API Key', is_mandatory=True)
    scopes = extract_connector_param(siemplify, param_name='Scopes', is_mandatory=False, default_value=DEFAULT_SCOPES)
    verify_ssl = extract_connector_param(siemplify, param_name='Verify SSL', default_value=True, input_type=bool)

    environment_field_name = extract_connector_param(siemplify, param_name='Environment Field Name', default_value=u'',
                                                     print_value=True)
    environment_regex_pattern = extract_connector_param(siemplify, param_name='Environment Regex Pattern',
                                                        default_value='', print_value=True)

    fetch_limit = extract_connector_param(siemplify, param_name='Max Alerts To Fetch', input_type=int,
                                          is_mandatory=False, default_value=50, print_value=True)
    hours_backwards = extract_connector_param(siemplify, param_name='Fetch Max Hours Backwards', input_type=int,
                                              is_mandatory=False, default_value=1, print_value=True)

    python_process_timeout = extract_connector_param(siemplify, param_name="PythonProcessTimeout", input_type=int,
                                                     is_mandatory=True, print_value=True)

    try:
        siemplify.LOGGER.info('------------------- Main - Started -------------------')

        manager = McAfeeMvisionEPOV2Manager(api_root, iam_root, client_id, client_secret, api_key, scopes, verify_ssl,
                                            siemplify.LOGGER)

        # Read already existing alerts ids
        siemplify.LOGGER.info("Loading existing ids from IDS file.")
        existing_ids = read_ids(siemplify, max_hours_backwards=HOURS_LIMIT_IN_IDS_FILE)
        siemplify.LOGGER.info('Found {} existing ids in ids.json'.format(len(existing_ids.keys())))

        last_success_time = get_last_success_time(siemplify=siemplify,
                                                  offset_with_metric={u'hours': hours_backwards})
        siemplify.LOGGER.info("Fetching events since {}".format(last_success_time.isoformat()))

        events = manager.get_events(
            start_time=last_success_time.isoformat(),
            limit=fetch_limit,
            asc=True,
            existing_ids=existing_ids.keys()
        )

        siemplify.LOGGER.info(u'Found {} new events.'.format(len(events)))

        if is_test_run:
            siemplify.LOGGER.info(u'This is a TEST run. Only 1 alert will be processed.')
            events = events[:1]

        for event in events:
            try:
                if len(processed_alerts) >= fetch_limit:
                    # Provide slicing for the alarms amount.
                    siemplify.LOGGER.info(
                        u'Reached max number of alerts cycle. No more alerts will be processed in this cycle.'
                    )
                    break

                siemplify.LOGGER.info(u'Started processing Alert {}'.format(event.event_id), alert_id=event.event_id)

                if is_approaching_timeout(python_process_timeout, connector_starting_time, TIMEOUT_THRESHOLD):
                    siemplify.LOGGER.info(u'Timeout is approaching. Connector will gracefully exit')
                    break

                existing_ids.update({event.event_id: unix_now()})

                alert_info = event.as_alert_info(
                    get_environment_common(siemplify, environment_field_name, environment_regex_pattern)
                )

                all_alerts.append(alert_info)

                siemplify.LOGGER.info(
                    "Event ID: {}, Analyzer Name: {}, Timestamp: {}, Threat Name: {}, Source IP: {}, Target IP: {}".format(
                        event.event_id, event.analyzer_name, event.timestamp, event.threat_name, event.source_ipv4,
                        event.target_ipv4
                    ))

                if is_overflowed(siemplify, alert_info, is_test_run):
                    siemplify.LOGGER.info(
                        u'{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping.'
                            .format(alert_name=alert_info.rule_generator,
                                    alert_identifier=alert_info.ticket_id,
                                    environment=alert_info.environment,
                                    product=alert_info.device_product))
                    # If is overflowed we should skip
                    continue

                processed_alerts.append(alert_info)
                siemplify.LOGGER.info(u'Alert {} was created.'.format(event.event_id))

            except Exception as e:
                siemplify.LOGGER.error(u'Failed to process Alert {}'.format(event.event_id), alert_id=event.event_id)
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            siemplify.LOGGER.info('Finished processing Alert {}'.format(event.event_id), alert_id=event.event_id)

        if not is_test_run:
            siemplify.LOGGER.info("Saving existing ids.")
            write_ids(siemplify, existing_ids)
            # Save timestamp based on the processed events (processed = alert info created, regardless of overflow
            # status). New timestamp should be the latest among all of those
            save_timestamp(siemplify=siemplify, alerts=all_alerts, timestamp_key='end_time')

    except Exception as err:
        siemplify.LOGGER.error('Got exception on main handler. Error: {}'.format(err))
        siemplify.LOGGER.exception(err)
        if is_test_run:
            raise

    siemplify.LOGGER.info('Created total of {} cases'.format(len(processed_alerts)))
    siemplify.LOGGER.info('------------------- Main - Finished -------------------')
    siemplify.return_package(processed_alerts)


if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == u'True')
    main(is_test)
