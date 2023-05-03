import datetime
import sys

from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyUtils import output_handler, unix_now

from EnvironmentCommon import GetEnvironmentCommonFactory
from PanoramaCommon import convert_server_time_to_datetime
from PanoramaConstants import (
    MAP_FILE,
    THREAT_LOG_CONNECTOR_NAME,
    ACCEPTABLE_TIME_INTERVAL_IN_MINUTES,
    CONNECTOR_LOG_TYPE,
    TIME_FORMAT
)
from PanoramaManager import PanoramaManager
from PanoramaValidator import PanoramaValidator
from TIPCommon import (
    extract_connector_param,
    read_ids,
    write_ids,
    is_approaching_timeout,
    is_overflowed,
    pass_whitelist_filter,
    siemplify_save_timestamp, get_last_success_time
)


@output_handler
def main(is_test_run):
    connector_starting_time = unix_now()
    alerts = []
    all_threat_logs = []
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = THREAT_LOG_CONNECTOR_NAME

    if is_test_run:
        siemplify.LOGGER.info(u'***** This is an \"IDE Play Button\" \"Run Connector once\" test run ******')

    siemplify.LOGGER.info(u'=' * 20 + u' Main - Params Init ' + u'=' * 20)

    environment = extract_connector_param(siemplify, param_name=u'Environment Field Name', input_type=unicode,
                                          is_mandatory=False, print_value=True)

    environment_regex = extract_connector_param(siemplify, param_name=u'Environment Regex Pattern', default_value=u'.*',
                                                input_type=unicode, is_mandatory=False, print_value=True)

    api_root = extract_connector_param(siemplify, param_name=u'API Root', input_type=unicode, is_mandatory=True,
                                       print_value=True)

    username = extract_connector_param(siemplify, param_name=u'Username', input_type=unicode, is_mandatory=True,
                                       print_value=False)

    password = extract_connector_param(siemplify, param_name=u'Password', input_type=unicode, is_mandatory=True,
                                       print_value=False)

    query_filter = extract_connector_param(siemplify, param_name=u'Query Filter', input_type=unicode,
                                           is_mandatory=False, print_value=True)

    severity = extract_connector_param(siemplify, param_name=u'Lowest Severity To Fetch', input_type=unicode,
                                       is_mandatory=True, print_value=True)

    offset_hours = extract_connector_param(siemplify, param_name=u'Fetch Max Hours Backwards', default_value=1,
                                           input_type=int, is_mandatory=False, print_value=True)

    limit = extract_connector_param(siemplify, param_name=u'Max Logs To Fetch', default_value=25,
                                    input_type=int, is_mandatory=False, print_value=True)

    whitelist_as_blacklist = extract_connector_param(siemplify, param_name=u'Use whitelist as a blacklist',
                                                     default_value=False, input_type=bool, is_mandatory=True,
                                                     print_value=True)

    verify_ssl = extract_connector_param(siemplify, param_name=u'Verify SSL', input_type=bool, is_mandatory=True,
                                         default_value=True, print_value=True)

    python_process_timeout = extract_connector_param(siemplify, param_name=u'PythonProcessTimeout',
                                                     default_value=180, input_type=int, is_mandatory=True,
                                                     print_value=True)

    try:
        PanoramaValidator.validate_severity(severity.lower())

        siemplify.LOGGER.info(u'=' * 20 + u' Main - Started ' + u'=' * 20)

        environment_common = GetEnvironmentCommonFactory.create_environment_manager(
            siemplify,
            environment_field_name=environment,
            environment_regex_pattern=environment_regex,
            map_file=MAP_FILE
        )

        panorama_manager = PanoramaManager(server_address=api_root, username=username, password=password,
                                           verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)

        server_time = panorama_manager.get_server_time()
        current_time = convert_server_time_to_datetime(server_time)
        start_time = current_time - datetime.timedelta(hours=offset_hours)

        # TODO -> Use last_success_time_datetime from TIPCommon when the timezone will be supported
        def get_last_timestamp():
            last_run_timestamp = siemplify.fetch_timestamp(datetime_format=True, timezone=current_time.tzinfo)
            is_first_run = start_time > last_run_timestamp
            return start_time if is_first_run else last_run_timestamp
        last_success_time_datetime = get_last_timestamp()

        if is_test_run:
            siemplify.LOGGER.info(u'This is a test run. Ignoring stored timestamps')

        existing_ids = read_ids(siemplify)

        if is_test_run:
            siemplify.LOGGER.info(u'This is a TEST run. Only 1 alert will be processed.')
            limit = 1

        fetched_threat_logs = panorama_manager.get_threat_logs(existing_ids=existing_ids,
                                                               log_type=CONNECTOR_LOG_TYPE,
                                                               query=query_filter,
                                                               last_success_time=last_success_time_datetime.
                                                               strftime(TIME_FORMAT),
                                                               max_logs_to_return=limit,
                                                               severity=severity,
                                                               server_time=server_time)

        siemplify.LOGGER.info(
            u'Fetched {} new threats since {}.'
            .format(len(fetched_threat_logs), last_success_time_datetime.isoformat())
        )

    except Exception as e:
        siemplify.LOGGER.error(unicode(e))
        siemplify.LOGGER.exception(e)
        sys.exit(1)

    for threat_log in fetched_threat_logs:
        try:
            if is_approaching_timeout(connector_starting_time, python_process_timeout):
                siemplify.LOGGER.info(u'Timeout is approaching. Connector will gracefully exit.')
                break

            if len(alerts) >= limit:
                siemplify.LOGGER.info(u'Stop processing alerts, limit {} reached'.format(limit))
                break

            siemplify.LOGGER.info(u'Processing threat {}'.format(threat_log.threat_id))

            if not threat_log.pass_time_filter():
                siemplify.LOGGER.info(
                    u'Threat {} is newer than {} minutes. Stopping connector...'
                    .format(threat_log.threat_id, ACCEPTABLE_TIME_INTERVAL_IN_MINUTES)
                )
                # Breaking connector loop because next threats can't pass acceptable time anyway.
                break

            all_threat_logs.append(threat_log)
            existing_ids.append(threat_log.threat_id)

            is_pass_whitelist_filter = pass_whitelist_filter(
                siemplify=siemplify,
                model=threat_log,
                model_key='threat_id',
                whitelist_as_a_blacklist=whitelist_as_blacklist
            )

            if not is_pass_whitelist_filter:
                siemplify.LOGGER.info(
                    u'Threat with id: {} and name: {} did not pass {} filter. Skipping...'
                    .format(threat_log.threat_id, threat_log.subtype, whitelist_as_blacklist)
                )
                continue

            siemplify.LOGGER.info(u'Started creating alert {}'.format(threat_log.threat_id),
                                  alert_id=threat_log.threat_id)
            alert_info = threat_log.to_alert_info(environment_common)
            siemplify.LOGGER.info(
                u'Finished creating Alert {}'
                .format(threat_log.threat_id),
                alert_id=threat_log.threat_id
            )

            if is_overflowed(siemplify, alert_info, is_test_run):
                siemplify.LOGGER.info(
                    u'{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping...'
                    .format(
                        alert_name=alert_info.rule_generator,
                        alert_identifier=alert_info.ticket_id,
                        environment=alert_info.environment,
                        product=alert_info.device_product
                    )
                )
                continue
            else:
                alerts.append(alert_info)
                siemplify.LOGGER.info(u'Alert {} was created.'.format(threat_log.threat_id))

        except Exception as e:
            siemplify.LOGGER.error(u'Failed to process threat {}'.format(threat_log.threat_id),
                                   alert_id=threat_log.threat_id)
            siemplify.LOGGER.exception(e)

            if is_test_run:
                raise

    if not is_test_run:
        if all_threat_logs:
            new_timestamp = all_threat_logs[-1].naive_time_converted_to_aware
            siemplify_save_timestamp(siemplify, new_timestamp=new_timestamp)
            siemplify.LOGGER.info(
                u'New timestamp {} has been saved'
                .format(new_timestamp.isoformat())
            )

        write_ids(siemplify, existing_ids)

    siemplify.LOGGER.info(u'Threats Processed: {} of {}'.format(len(alerts), len(all_threat_logs)))
    siemplify.LOGGER.info(u'Created total of {} alerts'.format(len(alerts)))

    siemplify.LOGGER.info(u'=' * 20 + u' Main - Finished ' + u'=' * 20)
    siemplify.return_package(alerts)


if __name__ == u'__main__':
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == u'True')
    main(is_test)
