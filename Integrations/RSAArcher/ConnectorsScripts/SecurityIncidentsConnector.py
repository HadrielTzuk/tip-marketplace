from SiemplifyUtils import output_handler, unix_now
from SiemplifyConnectors import SiemplifyConnectorExecution
from TIPCommon import extract_connector_param
from constants import CONNECTOR_NAME, WHITELIST_FILTER, BLACKLIST_FILTER, DEFAULT_TIME_FRAME, UNIX_FORMAT
from UtilsManager import read_ids, write_ids, get_last_success_time, is_approaching_timeout, \
    get_environment_common, is_overflowed, save_timestamp
from RSAArcherManager import RSAArcherManager
from SiemplifyConnectorsDataModel import AlertInfo
import sys


connector_starting_time = unix_now()


@output_handler
def main(is_test_run):
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = CONNECTOR_NAME
    processed_alerts = []

    if is_test_run:
        siemplify.LOGGER.info(u"***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******")

    siemplify.LOGGER.info(u"------------------- Main - Param Init -------------------")

    api_root = extract_connector_param(siemplify, param_name=u"API Root", is_mandatory=True, print_value=True)
    instance_name = extract_connector_param(siemplify, param_name=u"Instance Name", is_mandatory=True, print_value=True)
    username = extract_connector_param(siemplify, param_name=u"Username", is_mandatory=True, print_value=True)
    password = extract_connector_param(siemplify, param_name=u"Password", is_mandatory=True)
    verify_ssl = extract_connector_param(siemplify, param_name=u"Verify SSL", is_mandatory=True, input_type=bool,
                                         print_value=True)

    environment_field_name = extract_connector_param(siemplify, param_name=u"Environment Field Name")
    environment_regex_pattern = extract_connector_param(siemplify, param_name=u"Environment Regex Pattern")

    script_timeout = extract_connector_param(siemplify, param_name=u"PythonProcessTimeout", is_mandatory=True,
                                             input_type=int, print_value=True)
    fetch_limit = extract_connector_param(siemplify, param_name=u"Max Security Incidents To Fetch", input_type=int,
                                          print_value=True)
    hours_backwards = extract_connector_param(siemplify, param_name=u"Fetch Max Hours Backwards", input_type=int,
                                              default_value=DEFAULT_TIME_FRAME, print_value=True)

    process_security_alerts = extract_connector_param(siemplify, u"Process Security Alerts", is_mandatory=False,
                                                      input_type=bool, print_value=True)
    process_incident_journal = extract_connector_param(siemplify, u"Process Incident Journal", is_mandatory=False,
                                                       input_type=bool, print_value=True)
    time_format = extract_connector_param(siemplify, u"Time Format", is_mandatory=True, print_value=True)

    whitelist_as_a_blacklist = extract_connector_param(siemplify, u"Use whitelist as a blacklist", is_mandatory=True,
                                                       input_type=bool, print_value=True)
    whitelist_filter_type = BLACKLIST_FILTER if whitelist_as_a_blacklist else WHITELIST_FILTER
    whitelist = siemplify.whitelist

    try:
        siemplify.LOGGER.info(u"------------------- Main - Started -------------------")

        # Read already existing alerts ids
        siemplify.LOGGER.info(u"Reading already existing alerts ids...")
        existing_ids = read_ids(siemplify)

        siemplify.LOGGER.info(u"Fetching alerts...")
        manager = RSAArcherManager(api_root=api_root, username=username, password=password, instance_name=instance_name,
                                   verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER, siemplify=siemplify)
        fetched_alerts = []

        filtered_alerts = manager.get_alerts(
            existing_ids=existing_ids,
            limit=fetch_limit,
            start_timestamp=get_last_success_time(siemplify=siemplify, offset_with_metric={u"hours": hours_backwards},
                                                  time_format=UNIX_FORMAT),
            process_security_alerts=process_security_alerts,
            process_incident_journal=process_incident_journal,
            time_format=time_format
        )

        siemplify.LOGGER.info(u"Fetched {} alerts".format(len(filtered_alerts)))

        if is_test_run:
            siemplify.LOGGER.info(u"This is a TEST run. Only 1 alert will be processed.")
            filtered_alerts = filtered_alerts[:1]

        for alert in filtered_alerts:
            try:
                if len(processed_alerts) >= fetch_limit:
                    # Provide slicing for the alerts amount.
                    siemplify.LOGGER.info(
                        u"Reached max number of alerts cycle. No more alerts will be processed in this cycle."
                    )
                    break

                siemplify.LOGGER.info(u"Started processing alert {} - {}"
                                      .format(alert.id, alert.name), alert_id=alert.id)

                if is_approaching_timeout(connector_starting_time, script_timeout):
                    siemplify.LOGGER.info(u"Timeout is approaching. Connector will gracefully exit")
                    break

                # Update existing alerts
                existing_ids.append(alert.id)
                fetched_alerts.append(alert)

                if not pass_whitelist_filter(siemplify, alert, whitelist, whitelist_filter_type):
                    siemplify.LOGGER.info(u"Alert {} did not pass filters skipping...".format(alert.id))
                    continue

                alert_info = alert.get_alert_info(AlertInfo(), get_environment_common(siemplify, environment_field_name,
                                                                                      environment_regex_pattern))

                if is_overflowed(siemplify, alert_info, is_test_run):
                    siemplify.LOGGER.info(
                        u"{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping."
                        .format(alert_name=unicode(alert_info.rule_generator),
                                alert_identifier=unicode(alert_info.ticket_id),
                                environment=unicode(alert_info.environment),
                                product=unicode(alert_info.device_product)))
                    # If is overflowed we should skip
                    continue

                processed_alerts.append(alert_info)
                siemplify.LOGGER.info(u"Alert {} was created.".format(alert.id))

            except Exception as e:
                siemplify.LOGGER.error(u"Failed to process alert {}".format(alert.id), alert_id=alert.id)
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            siemplify.LOGGER.info(u"Finished processing alert {}".format(alert.id), alert_id=alert.id)

        if not is_test_run:
            save_timestamp(siemplify=siemplify, alerts=fetched_alerts, timestamp_key="date_created")
            write_ids(siemplify, existing_ids)

    except Exception as e:
        siemplify.LOGGER.error(u"Got exception on main handler. Error: {}".format(e))
        siemplify.LOGGER.exception(e)

        if is_test_run:
            raise

    siemplify.LOGGER.info(u"Created total of {} cases".format(len(processed_alerts)))
    siemplify.LOGGER.info(u"------------------- Main - Finished -------------------")
    siemplify.return_package(processed_alerts)


def pass_whitelist_filter(siemplify, alert, whitelist, whitelist_filter_type):
    # whitelist filter
    if whitelist:
        if whitelist_filter_type == BLACKLIST_FILTER and alert.name in whitelist:
            siemplify.LOGGER.info(u"Alert with name: {} did not pass blacklist filter.".format(alert.name))
            return False

        if whitelist_filter_type == WHITELIST_FILTER and alert.name not in whitelist:
            siemplify.LOGGER.info(u"Alert with name: {} did not pass whitelist filter.".format(alert.name))
            return False

    return True


if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == u"True")
    main(is_test)
