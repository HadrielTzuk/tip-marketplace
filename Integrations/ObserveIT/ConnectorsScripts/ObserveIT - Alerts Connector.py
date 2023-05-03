import sys
import os
from datetime import timedelta

from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyUtils import output_handler, utc_now, convert_string_to_datetime, convert_datetime_to_unix_time, unix_now
from EnvironmentCommon import EnvironmentHandle
from TIPCommon import extract_connector_param, validate_map_file

from ObserveITManager import ObserveITManager
from ObserveITValidator import ObserveITValidator
from ObserveITCommon import ObserveITCommon
from ObserveITConstants import (
    IDS_FILE,
    MAP_FILE,
    ALERTS_CONNECTOR_NAME,
    WHITELIST_FILTER,
    BLACKLIST_FILTER,
    ACCEPTABLE_TIME_INTERVAL_IN_MINUTES
)


@output_handler
def main(is_test_run):
    connector_starting_time = unix_now()
    alerts = []
    all_alerts = []
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = ALERTS_CONNECTOR_NAME

    if is_test_run:
        siemplify.LOGGER.info(u'***** This is an \"IDE Play Button\" \"Run Connector once\" test run ******')

    siemplify.LOGGER.info(u'=' * 20 + u' Main - Params Init ' + u'=' * 20)

    environment = extract_connector_param(
        siemplify,
        param_name=u'Environment Field Name',
        input_type=unicode,
        is_mandatory=False,
        print_value=True
    )

    environment_regex = extract_connector_param(
        siemplify,
        param_name=u'Environment Regex Pattern',
        input_type=unicode,
        is_mandatory=False,
        print_value=True
    )

    api_root = extract_connector_param(
        siemplify,
        param_name=u'API Root',
        input_type=unicode,
        is_mandatory=True,
        print_value=True
    )

    client_id = extract_connector_param(
        siemplify,
        param_name=u'Client ID',
        input_type=unicode,
        is_mandatory=True,
        print_value=False
    )

    client_secret = extract_connector_param(
        siemplify,
        param_name=u'Client Secret',
        input_type=unicode,
        is_mandatory=True,
        print_value=False
    )

    severity = extract_connector_param(
        siemplify,
        param_name=u'Lowest Severity To Fetch',
        input_type=unicode,
        is_mandatory=True,
        print_value=True
    )

    offset_hours = extract_connector_param(
        siemplify,
        param_name=u'Fetch Max Hours Backwards',
        input_type=int,
        is_mandatory=False,
        print_value=True
    )

    limit = extract_connector_param(
        siemplify,
        param_name=u'Max Alerts To Fetch',
        input_type=int,
        is_mandatory=False,
        print_value=True
    )

    whitelist_as_blacklist = extract_connector_param(
        siemplify,
        param_name=u'Use whitelist as a blacklist',
        input_type=bool,
        is_mandatory=True,
        print_value=True
    )

    verify_ssl = extract_connector_param(
        siemplify,
        param_name=u'Use SSL',
        input_type=bool,
        is_mandatory=True,
        print_value=True
    )

    python_process_timeout = extract_connector_param(
        siemplify,
        param_name=u'PythonProcessTimeout',
        input_type=int,
        is_mandatory=True,
        print_value=True
    )

    try:
        ObserveITValidator.validate_severity(severity)

        whitelist_as_blacklist = BLACKLIST_FILTER if whitelist_as_blacklist else WHITELIST_FILTER

        siemplify.LOGGER.info(u'=' * 20 + u' Main - Started ' + u'=' * 20)

        map_file_path = os.path.join(siemplify.run_folder, MAP_FILE)
        validate_map_file(siemplify, map_file_path)

        observe_it_common = ObserveITCommon(siemplify.LOGGER)
        environment_common = EnvironmentHandle(
            map_file_path,
            siemplify.LOGGER,
            environment,
            environment_regex,
            siemplify.context.connector_info.environment
        )

        if is_test_run:
            siemplify.LOGGER.info(u'This is a test run. Ignoring stored timestamps')
            last_success_time_datetime = observe_it_common.validate_timestamp(
                utc_now() - timedelta(hours=offset_hours), offset_hours
            )
        else:
            last_success_time_datetime = observe_it_common.validate_timestamp(
                siemplify.fetch_timestamp(datetime_format=True), offset_hours
            )

        # Read already existing alerts ids
        existing_ids_file_path = os.path.join(siemplify.run_folder, IDS_FILE)
        existing_ids = observe_it_common.read_ids(existing_ids_file_path)

        observe_it_manager = ObserveITManager(
            api_root=api_root,
            client_id=client_id,
            client_secret=client_secret,
            verify_ssl=verify_ssl
        )

        if is_test_run:
            siemplify.LOGGER.info(u'This is a TEST run. Only 1 alert will be processed.')
            limit = 1

        fetched_alerts = observe_it_manager.get_alerts(
            severity=severity,
            timestamp=convert_datetime_to_unix_time(last_success_time_datetime),
            limit=limit
        )

        siemplify.LOGGER.info(
            u'Fetched {} incidents since {}.'
            .format(len(fetched_alerts), last_success_time_datetime.isoformat())
        )

        filtered_alerts = observe_it_common.filter_old_ids(
            alerts=fetched_alerts,
            existing_ids=existing_ids
        )

        siemplify.LOGGER.info(
            u'Filtered {} new incidents since {}.'
            .format(len(filtered_alerts), last_success_time_datetime.isoformat())
        )

        filtered_alerts = sorted(filtered_alerts, key=lambda inc: inc.rising_value)
    except Exception as e:
        siemplify.LOGGER.error(unicode(e))
        siemplify.LOGGER.exception(e)
        sys.exit(1)

    for alert in filtered_alerts:
        try:
            if observe_it_common.is_approaching_timeout(connector_starting_time, python_process_timeout):
                siemplify.LOGGER.info(u'Timeout is approaching. Connector will gracefully exit.')
                break

            if len(alerts) >= limit:
                siemplify.LOGGER.info(u'Stop processing alerts, limit {} reached'.format(limit))
                break

            siemplify.LOGGER.info(u'Processing alert {}'.format(alert.id))

            if not alert.pass_time_filter():
                siemplify.LOGGER.info(
                    u'Alert {} is newer than {} minutes. Stopping connector...'
                    .format(alert.id, ACCEPTABLE_TIME_INTERVAL_IN_MINUTES)
                )
                # Breaking connector loop because next alerts can't pass acceptable time anyway.
                break

            all_alerts.append(alert)
            existing_ids.append(alert.id)

            if not alert.pass_whitelist_or_blacklist_filter(siemplify.whitelist, whitelist_as_blacklist):
                siemplify.LOGGER.info(
                    u'Alert with id: {} and name: {} did not pass {} filter. Skipping...'
                    .format(alert.id, alert.rule_name, whitelist_as_blacklist)
                )
                continue

            is_overflowed = False
            siemplify.LOGGER.info(u'Started creating alert {}'.format(alert.id), alert_id=alert.id)
            alert_info = alert.to_alert_info(environment_common)
            siemplify.LOGGER.info(
                u'Finished creating Alert {}'
                .format(alert.id),
                alert_id=alert.id
            )

            try:
                is_overflowed = siemplify.is_overflowed_alert(
                    environment=alert_info.environment,
                    alert_identifier=alert_info.ticket_id,
                    alert_name=alert_info.rule_generator,
                    product=alert_info.device_product
                )

            except Exception as e:
                siemplify.LOGGER.error(u'Error validation connector overflow, ERROR: {}'.format(e))
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            if is_overflowed:
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
                siemplify.LOGGER.info(u'Alert {} was created.'.format(alert.id))

        except Exception as e:
            siemplify.LOGGER.error(u'Failed to process incident {}'.format(alert.id), alert_id=alert.id)
            siemplify.LOGGER.exception(e)

            if is_test_run:
                raise

    if not is_test_run:
        if all_alerts:
            new_timestamp = convert_string_to_datetime(all_alerts[-1].rising_value)
            siemplify.save_timestamp(new_timestamp=new_timestamp)
            siemplify.LOGGER.info(
                u'New timestamp {} has been saved'
                .format(new_timestamp.isoformat())
            )

        observe_it_common.write_ids(existing_ids_file_path, existing_ids)

    siemplify.LOGGER.info(u'Alerts Processed: {} of {}'.format(len(alerts), len(all_alerts)))
    siemplify.LOGGER.info(u'Created total of {} alerts'.format(len(alerts)))

    siemplify.LOGGER.info(u'=' * 20 + u' Main - Finished ' + u'=' * 20)
    siemplify.return_package(alerts)


if __name__ == u'__main__':
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == u'True')
    main(is_test_run)
