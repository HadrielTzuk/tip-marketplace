import sys
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyUtils import output_handler, unix_now
from FireEyeHXManager import FireEyeHXManager
from TIPCommon import extract_connector_param, get_last_success_time, is_overflowed, save_timestamp, is_approaching_timeout
from EnvironmentCommon import GetEnvironmentCommonFactory
from SiemplifyConnectorsDataModel import AlertInfo

# =====================================
#             CONSTANTS               #
# =====================================
CONNECTOR_NAME = u'FireEye HX Alerts Connector'
WHITELIST_FILTER = u'whitelist'
BLACKLIST_FILTER = u'blacklist'
connector_starting_time = unix_now()
TIMEOUT_THRESHOLD = 0.9


@output_handler
def main(is_test_run):
    processed_alerts = []
    siemplify = SiemplifyConnectorExecution()  # Siemplify main SDK wrapper
    siemplify.script_name = CONNECTOR_NAME

    if is_test_run:
        siemplify.LOGGER.info(u'***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******')

    siemplify.LOGGER.info(u'------------------- Main - Param Init -------------------')

    api_root = extract_connector_param(siemplify, param_name=u'API Root', is_mandatory=True)
    username = extract_connector_param(siemplify, param_name=u'Username', is_mandatory=True)
    password = extract_connector_param(siemplify, param_name=u'Password', is_mandatory=True)
    verify_ssl = extract_connector_param(siemplify, param_name=u'Verify SSL', default_value=True, input_type=bool)

    environment_field_name = extract_connector_param(siemplify, param_name=u'Environment Field Name', default_value=u'')
    environment_regex_pattern = extract_connector_param(siemplify, param_name=u'Environment Regex Pattern',
                                                        default_value=u'')

    fetch_limit = extract_connector_param(siemplify, param_name=u'Max Alerts Per Cycle', input_type=int)
    hours_backwards = extract_connector_param(siemplify, param_name=u'Offset time in hours', input_type=int)
    alert_type = extract_connector_param(siemplify, param_name=u'Alert Type')

    whitelist_as_a_blacklist = extract_connector_param(siemplify, u'Use whitelist as a blacklist',
                                                       is_mandatory=True, input_type=bool, print_value=True)
    whitelist_filter_type = BLACKLIST_FILTER if whitelist_as_a_blacklist else WHITELIST_FILTER

    whitelist = siemplify.whitelist

    python_process_timeout = extract_connector_param(siemplify, param_name=u"PythonProcessTimeout", input_type=int,
                                                     is_mandatory=True, print_value=True)
    try:
        siemplify.LOGGER.info(u'------------------- Main - Started -------------------')

        siemplify.LOGGER.info(u'Fetching alerts...')
        manager = FireEyeHXManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl)

        fetched_alerts = []
        filtered_alerts = manager.get_alerts_for_connector(
            start_time=get_last_success_time(siemplify=siemplify,
                                             offset_with_metric={u'hours': hours_backwards}).strftime('%Y-%m-%dT%H:%M:%S.%f'),
            limit=fetch_limit,
            alert_type=alert_type)

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

                siemplify.LOGGER.info(u'Started processing Alert {}'.format(alert._id), alert_id=alert._id)

                if is_approaching_timeout(connector_starting_time, python_process_timeout):
                    siemplify.LOGGER.info(u'Timeout is approaching. Connector will gracefully exit')
                    break

                fetched_alerts.append(alert)

                if not pass_whitelist_filter(siemplify, alert, whitelist, whitelist_filter_type):
                    siemplify.LOGGER.info(u'Alert {} did not pass filters skipping....'.format(alert._id))
                    continue

                # attach additional host info
                alert.attach_host_info(manager.get_host_information(siemplify, alert.host_id))

                alert_info = alert.get_alert_info(
                    AlertInfo(),
                    GetEnvironmentCommonFactory.create_environment_manager(
                        siemplify, environment_field_name, environment_regex_pattern)
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
                siemplify.LOGGER.info(u'Alert {} was created.'.format(alert._id))

            except Exception as e:
                siemplify.LOGGER.error(u'Failed to process alert {}'.format(alert._id), alert_id=alert._id)
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            siemplify.LOGGER.info(u'Finished processing Alert {}'.format(alert._id), alert_id=alert._id)

        if not is_test_run:
            save_timestamp(siemplify=siemplify, alerts=fetched_alerts)

        manager.close_connection()
    except Exception as err:
        siemplify.LOGGER.error(u'Got exception on main handler. Error: {0}'.format(err))
        siemplify.LOGGER.exception(err)
        if is_test_run:
            raise

    siemplify.LOGGER.info(u'Created total of {} cases'.format(len(processed_alerts)))
    siemplify.LOGGER.info(u'------------------- Main - Finished -------------------')
    siemplify.return_package(processed_alerts)


def pass_whitelist_filter(siemplify, alert, whitelist, whitelist_filter_type):
    # whitelist filter
    if whitelist:
        if whitelist_filter_type == BLACKLIST_FILTER and alert.type in whitelist:
            siemplify.LOGGER.info(u"Alert with type: {} did not pass blacklist filter.".format(alert.type))
            return False

        if whitelist_filter_type == WHITELIST_FILTER and alert.type not in whitelist:
            siemplify.LOGGER.info(u"Alert with type: {} did not pass whitelist filter.".format(alert.type))
            return False

    return True


if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == u'True')
    main(is_test)
