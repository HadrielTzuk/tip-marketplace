from SiemplifyUtils import output_handler, unix_now, utc_now, convert_datetime_to_unix_time
from SiemplifyConnectors import SiemplifyConnectorExecution
from TIPCommon import (
    extract_connector_param,
    read_ids,
    write_ids,
    get_last_success_time,
    is_approaching_timeout,
    is_overflowed,
    save_timestamp,
    UNIX_FORMAT
)
from EnvironmentCommon import GetEnvironmentCommonFactory
from constants import CONNECTOR_NAME, DEFAULT_TIME_FRAME, MAX_LIMIT, DEFAULT_LIMIT, MAX_FETCH_HOURS
from utils import pass_severity_filter, pass_whitelist_filter
from SophosManager import SophosManagerForConnector as SophosManager
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
    api_key = extract_connector_param(siemplify, param_name=u"API Key", is_mandatory=True)
    auth_token = extract_connector_param(siemplify, param_name=u"Base 64 Auth Payload", is_mandatory=True)
    verify_ssl = extract_connector_param(siemplify, param_name=u"Verify SSL", is_mandatory=True, input_type=bool,
                                         print_value=True)

    environment_field_name = extract_connector_param(siemplify, param_name=u"Environment Field Name", print_value=True)
    environment_regex_pattern = extract_connector_param(siemplify, param_name=u"Environment Regex Pattern",
                                                        print_value=True)

    script_timeout = extract_connector_param(siemplify, param_name=u"PythonProcessTimeout", is_mandatory=True,
                                             input_type=int, print_value=True)
    lowest_severity_to_fetch = extract_connector_param(siemplify, param_name=u"Lowest Severity To Fetch",
                                                       print_value=True)
    hours_backwards = extract_connector_param(siemplify, param_name=u"Max Hours Backwards",
                                              input_type=int, default_value=DEFAULT_TIME_FRAME, print_value=True)
    fetch_limit = extract_connector_param(siemplify, param_name=u"Max Alerts To Fetch", input_type=int,
                                          default_value=DEFAULT_LIMIT, print_value=True)
    whitelist_as_a_blacklist = extract_connector_param(siemplify, u"Use whitelist as a blacklist", is_mandatory=True,
                                                       input_type=bool, print_value=True)
    device_product_field = extract_connector_param(siemplify, u"DeviceProductField", is_mandatory=True)

    try:
        siemplify.LOGGER.info(u"------------------- Main - Started -------------------")

        if fetch_limit > MAX_LIMIT:
            siemplify.LOGGER.info(u"Max Alerts To Fetch exceeded the maximum limit of {}. "
                                  u"The default value {} will be used".format(MAX_LIMIT, DEFAULT_LIMIT))
            fetch_limit = DEFAULT_LIMIT
        elif fetch_limit < 0:
            siemplify.LOGGER.info(u"Max Alerts To Fetch must be non-negative. "
                                  u"The default value {} will be used".format(DEFAULT_LIMIT))
            fetch_limit = DEFAULT_LIMIT

        if hours_backwards > 24:
            siemplify.LOGGER.info(u"Max Hours Backwards exceeded the maximum limit of {}. "
                                  u"The default value {} will be used".format(MAX_FETCH_HOURS, DEFAULT_TIME_FRAME))
            hours_backwards = DEFAULT_TIME_FRAME
        elif hours_backwards < 0:
            siemplify.LOGGER.info(u"Max Hours Backwards must be non-negative. "
                                  u"The default value {} will be used".format(DEFAULT_TIME_FRAME))
            hours_backwards = DEFAULT_TIME_FRAME

        # Read already existing alerts ids
        existing_ids = read_ids(siemplify)
        siemplify.LOGGER.info(u"Successfully loaded {} existing ids".format(len(existing_ids)))

        manager = SophosManager(verify_ssl=verify_ssl,
                                api_root=api_root,
                                api_key=api_key,
                                api_token=auth_token,
                                siemplify=siemplify)

        last_success_time = get_last_success_time(siemplify=siemplify, offset_with_metric={"hours": hours_backwards},
                                                  time_format=UNIX_FORMAT)

        fetched_alerts = []
        filtered_alerts = manager.get_alerts(
            existing_ids=existing_ids,
            limit=fetch_limit,
            start_time=last_success_time
        )

        siemplify.LOGGER.info(u"Fetched {} alerts".format(len(filtered_alerts)))

        if is_test_run:
            siemplify.LOGGER.info(u"This is a TEST run. Only 1 alert will be processed.")
            filtered_alerts = filtered_alerts[:1]

        for alert in filtered_alerts:
            try:
                if is_approaching_timeout(script_timeout, connector_starting_time):
                    siemplify.LOGGER.info(u"Timeout is approaching. Connector will gracefully exit")
                    break

                if len(processed_alerts) >= fetch_limit:
                    # Provide slicing for the alerts amount.
                    siemplify.LOGGER.info(
                        u"Reached max number of alerts cycle. No more alerts will be processed in this cycle."
                    )
                    break

                siemplify.LOGGER.info(u"Started processing alert {} - {}".format(alert.id, alert.threat))

                # Update existing alerts
                existing_ids.append(alert.id)
                fetched_alerts.append(alert)

                if not pass_filters(siemplify, whitelist_as_a_blacklist, alert, u"alert_type", lowest_severity_to_fetch):
                    continue

                alert_info = alert.get_alert_info(
                    AlertInfo(),
                    GetEnvironmentCommonFactory.create_environment_manager(
                        siemplify,
                        environment_field_name,
                        environment_regex_pattern
                    ),
                    device_product_field)

                if is_overflowed(siemplify, alert_info, is_test_run):
                    siemplify.LOGGER.info(
                        u'{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping...'
                            .format(alert_name=alert_info.rule_generator,
                                    alert_identifier=alert_info.ticket_id,
                                    environment=alert_info.environment,
                                    product=alert_info.device_product))
                    # If is overflowed we should skip
                    continue

                processed_alerts.append(alert_info)
                siemplify.LOGGER.info(u"Alert {} was created.".format(alert.id))

            except Exception as e:
                siemplify.LOGGER.error(u"Failed to process incident {}".format(alert.id))
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            siemplify.LOGGER.info(u"Finished processing incident {}".format(alert.id))

        if not is_test_run:
            siemplify.LOGGER.info(u"Saving existing ids.")
            write_ids(siemplify, existing_ids)
            save_timestamp(
                siemplify=siemplify,
                alerts=fetched_alerts,
                timestamp_key=u"when",
                convert_a_string_timestamp_to_unix=True
            )

    except Exception as e:
        siemplify.LOGGER.error(u"Got exception on main handler. Error: {}".format(e))
        siemplify.LOGGER.exception(e)

        if is_test_run:
            raise

    siemplify.LOGGER.info(u"Created total of {} cases".format(len(processed_alerts)))
    siemplify.LOGGER.info(u"------------------- Main - Finished -------------------")
    siemplify.return_package(processed_alerts)


def pass_filters(siemplify, whitelist_as_a_blacklist, alert, model_key, lowest_severity_to_fetch):
    # All alert filters should be checked here
    if not pass_whitelist_filter(siemplify, whitelist_as_a_blacklist, alert, model_key):
        return False

    if not pass_severity_filter(siemplify, alert, lowest_severity_to_fetch):
        return False

    return True


if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == "True")
    main(is_test)
