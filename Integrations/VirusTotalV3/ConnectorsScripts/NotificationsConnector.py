from SiemplifyUtils import output_handler, unix_now
from SiemplifyConnectors import SiemplifyConnectorExecution
from TIPCommon import extract_connector_param, read_ids, write_ids, get_last_success_time, \
    DATETIME_FORMAT, is_approaching_timeout, save_timestamp, is_overflowed
from constants import CONNECTOR_NAME, DEFAULT_NOTIFICATIONS_LIMIT, DEFAULT_TIME_FRAME, TIMESTAMP_KEY
from UtilsManager import pass_whitelist_filter, convert_comma_separated_to_list, datetime_to_rfc3339, \
    convert_list_to_comma_string
from VirusTotalManager import VirusTotalManager
from SiemplifyConnectorsDataModel import AlertInfo
import sys
from EnvironmentCommon import GetEnvironmentCommonFactory


connector_starting_time = unix_now()


@output_handler
def main(is_test_run):
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = CONNECTOR_NAME
    processed_alerts = []

    if is_test_run:
        siemplify.LOGGER.info("***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******")

    siemplify.LOGGER.info("------------------- Main - Param Init -------------------")

    api_key = extract_connector_param(siemplify, param_name="API Key", is_mandatory=True)
    verify_ssl = extract_connector_param(siemplify, param_name="Verify SSL", is_mandatory=True, input_type=bool,
                                         print_value=True)
    environment_field_name = extract_connector_param(siemplify, param_name="Environment Field Name", print_value=True)
    environment_regex_pattern = extract_connector_param(siemplify, param_name="Environment Regex Pattern",
                                                        print_value=True)

    script_timeout = extract_connector_param(siemplify, param_name="PythonProcessTimeout", is_mandatory=True,
                                             input_type=int, print_value=True)
    percentage_threshold = extract_connector_param(siemplify, param_name="Engine Percentage Threshold To Fetch",
                                                   is_mandatory=True, input_type=int, print_value=True)
    engine_whitelist_str = extract_connector_param(siemplify, param_name="Engine Whitelist", is_mandatory=False,
                                                   print_value=True)
    hours_backwards = extract_connector_param(siemplify, param_name="Max Hours Backwards", input_type=int,
                                              default_value=DEFAULT_TIME_FRAME, print_value=True)
    fetch_limit = extract_connector_param(siemplify, param_name="Max Notifications To Fetch", input_type=int,
                                          default_value=DEFAULT_NOTIFICATIONS_LIMIT, print_value=True)
    whitelist_as_a_blacklist = extract_connector_param(siemplify, "Use dynamic list as a blacklist", is_mandatory=True,
                                                       input_type=bool, print_value=True)
    device_product_field = extract_connector_param(siemplify, "DeviceProductField", is_mandatory=True)
    engine_whitelist = convert_comma_separated_to_list(engine_whitelist_str)

    try:
        siemplify.LOGGER.info("------------------- Main - Started -------------------")

        if hours_backwards < 1:
            siemplify.LOGGER.info(f"Max Hours Backwards must be greater than zero. The default value {DEFAULT_TIME_FRAME} "
                                  f"will be used")
            hours_backwards = DEFAULT_TIME_FRAME

        if fetch_limit < 1:
            siemplify.LOGGER.info(f"Max Notifications To Fetch must be greater than zero. The default value "
                                  f"{DEFAULT_NOTIFICATIONS_LIMIT} will be used")
            fetch_limit = DEFAULT_NOTIFICATIONS_LIMIT

        if percentage_threshold > 100 or percentage_threshold < 0:
            raise Exception(f"value for the parameter \"Engine Percentage Threshold To Fetch\" is invalid. "
                            f"Please check it. The value should be in range from 0 to 100")

        # Read already existing alerts ids
        existing_ids = read_ids(siemplify)
        siemplify.LOGGER.info(f"Successfully loaded {len(existing_ids)} existing alerts from ids file")

        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)

        last_success_time = get_last_success_time(siemplify=siemplify,
                                                  offset_with_metric={"hours": hours_backwards},
                                                  time_format=DATETIME_FORMAT)

        fetched_alerts = []

        notifications = manager.get_livehunt_notifications(start_timestamp=datetime_to_rfc3339(last_success_time),
                                                           limit=fetch_limit, siemplify=siemplify,
                                                           existing_ids=existing_ids)

        siemplify.LOGGER.info(f"Fetched {len(notifications)} alerts")

        if is_test_run:
            siemplify.LOGGER.info("This is a TEST run. Only 1 alert will be processed.")
            notifications = notifications[:1]

        for alert in notifications:
            try:
                if is_approaching_timeout(connector_starting_time, script_timeout):
                    siemplify.LOGGER.info("Timeout is approaching. Connector will gracefully exit")
                    break

                if len(processed_alerts) >= fetch_limit:
                    # Provide slicing for the alerts amount.
                    siemplify.LOGGER.info(
                        "Reached max number of alerts cycle. No more alerts will be processed in this cycle."
                    )
                    break

                siemplify.LOGGER.info(f"Started processing alert {alert.id}")
                alert.set_supported_engines(engine_whitelist)

                if engine_whitelist and not alert.supported_engines:
                    siemplify.LOGGER.warn("None of the provided engines are available and will be ignored.")
                elif alert.invalid_engines:
                    siemplify.LOGGER.warn(f"Following engines are not available and will be ignored: "
                                          f"{convert_list_to_comma_string(alert.invalid_engines)}")

                # Update existing alerts
                existing_ids.append(alert.id)
                fetched_alerts.append(alert)

                if not pass_filters(siemplify, whitelist_as_a_blacklist, alert, "rule_name", percentage_threshold):
                    continue

                alert_info = alert.get_alert_info(
                    alert_info=AlertInfo(),
                    environment_common=GetEnvironmentCommonFactory().create_environment_manager(
                        siemplify, environment_field_name, environment_regex_pattern),
                    device_product_field=device_product_field
                )

                if is_overflowed(siemplify, alert_info, is_test_run):
                    siemplify.LOGGER.info(
                        f"{alert_info.rule_generator}-{alert_info.ticket_id}-{alert_info.environment}"
                        f"-{alert_info.device_product} found as overflow alert. Skipping...")
                    # If is overflowed we should skip
                    continue

                processed_alerts.append(alert_info)
                siemplify.LOGGER.info(f"Alert {alert.id} was created.")

            except Exception as e:
                siemplify.LOGGER.error(f"Failed to process alert {alert.id}")
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            siemplify.LOGGER.info(f"Finished processing alert {alert.id}")

        if not is_test_run:
            siemplify.LOGGER.info("Saving existing ids.")
            write_ids(siemplify, existing_ids)
            save_timestamp(siemplify=siemplify, alerts=fetched_alerts, timestamp_key=TIMESTAMP_KEY,
                           convert_timestamp_to_micro_time=True)

    except Exception as e:
        siemplify.LOGGER.error(f"Got exception on main handler. Error: {e}")
        siemplify.LOGGER.exception(e)

        if is_test_run:
            raise

    siemplify.LOGGER.info(f"Created total of {len(processed_alerts)} cases")
    siemplify.LOGGER.info("------------------- Main - Finished -------------------")
    siemplify.return_package(processed_alerts)


def pass_filters(siemplify, whitelist_as_a_blacklist, alert, model_key, percentage_threshold):
    # All alert filters should be checked here
    if int(alert.percentage_threshold) < percentage_threshold:
        siemplify.LOGGER.info(f"Alert with id: {alert.id} did not pass engine threshold.")
        return False

    if not pass_whitelist_filter(siemplify, whitelist_as_a_blacklist, alert, model_key):
        return False

    return True


if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == "True")
    main(is_test)
