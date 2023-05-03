from SiemplifyUtils import output_handler, unix_now
from SiemplifyConnectors import SiemplifyConnectorExecution
from TIPCommon import (
    extract_connector_param,
    read_ids,
    write_ids,
    filter_old_alerts,
    get_last_success_time,
    is_approaching_timeout,
    save_timestamp,
    is_overflowed,
    convert_list_to_comma_string,
    pass_whitelist_filter,
    UNIX_FORMAT
)
from constants import (
    IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_NAME,
    IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_DEFAULT_SEVERITY,
    IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_DEFAULT_MAX_HOURS_BACKWARDS,
    IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_DEFAULT_LIMIT,
    IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_SEVERITY_MAPPING,
    DEFAULT_MAX_LIMIT
)
from CrowdStrikeManager import CrowdStrikeManager
from SiemplifyConnectorsDataModel import AlertInfo
from EnvironmentCommon import GetEnvironmentCommonFactory
import sys


connector_starting_time = unix_now()


@output_handler
def main(is_test_run):
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_NAME
    processed_alerts = []

    if is_test_run:
        siemplify.LOGGER.info('***** This is an \'IDE Play Button\' \'Run Connector once\' test run ******')

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_connector_param(siemplify, param_name='API Root', is_mandatory=True, print_value=True)
    client_id = extract_connector_param(siemplify, param_name='Client ID', is_mandatory=True, print_value=True)
    client_secret = extract_connector_param(siemplify, param_name='Client Secret', is_mandatory=True)
    verify_ssl = extract_connector_param(siemplify, param_name='Verify SSL', input_type=bool, is_mandatory=True,
                                         print_value=True)

    environment_field_name = extract_connector_param(siemplify, param_name='Environment Field Name', print_value=True)
    environment_regex_pattern = extract_connector_param(siemplify, param_name='Environment Regex Pattern',
                                                        print_value=True)

    script_timeout = extract_connector_param(siemplify, param_name='PythonProcessTimeout', input_type=int,
                                             print_value=True)
    lowest_severity = extract_connector_param(siemplify, param_name='Lowest Severity Score To Fetch', print_value=True,
                                              default_value=IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_DEFAULT_SEVERITY)
    max_hours_backwards = extract_connector_param(siemplify, param_name='Max Hours Backwards', input_type=int,
                                                  default_value=IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_DEFAULT_MAX_HOURS_BACKWARDS,
                                                  print_value=True)
    limit = extract_connector_param(siemplify, param_name='Max Detections To Fetch', input_type=int,
                                    default_value=IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_DEFAULT_LIMIT,
                                    print_value=True)
    whitelist_as_a_blocklist = extract_connector_param(siemplify, param_name="Use dynamic list as a blocklist",
                                                       input_type=bool, is_mandatory=True, print_value=True)

    siemplify.LOGGER.info('------------------- Main - Started -------------------')

    try:
        if max_hours_backwards < 1:
            siemplify.LOGGER.info(f"Max Hours Backwards must be greater than zero. The default value "
                                  f"{IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_DEFAULT_MAX_HOURS_BACKWARDS} will"
                                  f" be used")
            max_hours_backwards = IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_DEFAULT_MAX_HOURS_BACKWARDS

        if limit < 1:
            siemplify.LOGGER.info(f"Max Detections To Fetch must be greater than zero. The default value "
                                  f"{IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_DEFAULT_LIMIT} will be used")
            limit = IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_DEFAULT_LIMIT

        try:
            lowest_severity = int(lowest_severity)
            if lowest_severity < 0 or lowest_severity > 100:
                raise Exception(
                    f"invalid int value provided for the parameter \"Lowest Severity Score To Fetch\"."
                    f"Supported values are in range 0 to 100."
                )
        except ValueError:
            lowest_severity = lowest_severity.lower()
            if lowest_severity not in IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_SEVERITY_MAPPING:
                raise Exception(
                    f"Invalid value provided for the parameter \"Lowest Severity Score To Fetch\". "
                    f"Supported values: "
                    f"{convert_list_to_comma_string(list(IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_SEVERITY_MAPPING.keys()))}."
                )

            lowest_severity = IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_SEVERITY_MAPPING.get(lowest_severity)

        # Read already existing alerts ids
        existing_ids = read_ids(siemplify)
        siemplify.LOGGER.info(f"Successfully loaded {len(existing_ids)} existing alert ids")

        manager = CrowdStrikeManager(client_id=client_id, client_secret=client_secret, use_ssl=verify_ssl,
                                     api_root=api_root)

        fetched_alerts = []

        alerts = manager.get_alerts(
            start_timestamp=get_last_success_time(siemplify=siemplify,
                                                  offset_with_metric={"hours": max_hours_backwards},
                                                  time_format=UNIX_FORMAT),
            severity=lowest_severity,
            limit=max(DEFAULT_MAX_LIMIT, limit)
        )

        filtered_alerts = filter_old_alerts(siemplify, alerts, existing_ids, "alert_id")
        siemplify.LOGGER.info(f"Fetched {len(filtered_alerts)} alerts")

        if is_test_run:
            siemplify.LOGGER.info("This is a TEST run. Only 1 alert will be processed.")
            filtered_alerts = filtered_alerts[:1]

        for alert in filtered_alerts:
            try:
                if is_approaching_timeout(connector_starting_time, script_timeout):
                    siemplify.LOGGER.info("Timeout is approaching. Connector will gracefully exit")
                    break

                if len(processed_alerts) >= limit:
                    # Provide slicing for the alerts amount.
                    siemplify.LOGGER.info(
                        "Reached max number of alerts cycle. No more alerts will be processed in this cycle."
                    )
                    break

                siemplify.LOGGER.info(f"Started processing alert {alert.alert_id}")

                if not pass_filters(siemplify, whitelist_as_a_blocklist, alert, "display_name"):
                    # Update existing alerts
                    existing_ids.append(alert.alert_id)
                    fetched_alerts.append(alert)
                    continue

                # Set events
                alert.set_events()

                # Update existing alerts
                existing_ids.append(alert.alert_id)
                fetched_alerts.append(alert)

                alert_info = alert.get_alert_info(
                    alert_info=AlertInfo(),
                    environment_common=GetEnvironmentCommonFactory().create_environment_manager(
                        siemplify, environment_field_name, environment_regex_pattern)
                )

                if is_overflowed(siemplify, alert_info, is_test_run):
                    siemplify.LOGGER.info(
                        f"{alert_info.rule_generator}-{alert_info.ticket_id}-{alert_info.environment}"
                        f"-{alert_info.device_product} found as overflow alert. Skipping...")
                    # If is overflowed we should skip
                    continue

                processed_alerts.append(alert_info)
                siemplify.LOGGER.info(f"Alert {alert.alert_id} was created.")

            except Exception as e:
                siemplify.LOGGER.error(f"Failed to process alert {alert.alert_id}")
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            siemplify.LOGGER.info(f"Finished processing alert {alert.alert_id}")

        if not is_test_run:
            siemplify.LOGGER.info("Saving existing ids.")
            write_ids(siemplify, existing_ids)
            save_timestamp(siemplify=siemplify, alerts=fetched_alerts, timestamp_key="created_timestamp")

        siemplify.LOGGER.info(f"Alerts processed: {len(processed_alerts)} out of {len(fetched_alerts)}")

    except Exception as e:
        siemplify.LOGGER.error(f"Got exception on main handler. Error: {e}")
        siemplify.LOGGER.exception(e)

        if is_test_run:
            raise

    siemplify.LOGGER.info(f"Created total of {len(processed_alerts)} cases")
    siemplify.LOGGER.info('------------------- Main - Finished -------------------')
    siemplify.return_package(processed_alerts)


def pass_filters(siemplify, whitelist_as_a_blacklist, alert, model_key):
    # All alert filters should be checked here
    if not pass_whitelist_filter(siemplify, whitelist_as_a_blacklist, alert, model_key):
        return False

    return True


if __name__ == "__main__":
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == "True")
    main(is_test_run)
