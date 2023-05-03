from SiemplifyUtils import output_handler, unix_now
from SiemplifyConnectors import SiemplifyConnectorExecution
from TIPCommon import (
    extract_connector_param,
    read_ids,
    write_ids,
    get_last_success_time,
    is_approaching_timeout,
    save_timestamp,
    is_overflowed,
    convert_list_to_comma_string,
    convert_comma_separated_to_list,
    pass_whitelist_filter
)
from constants import (
    WHITELIST_FILTER,
    BLACKLIST_FILTER,
    DEFAULT_PRODUCT_FIELD_NAME,
    DEFAULT_MAX_HOURS_BACKWARDS,
    DEFAULT_MAX_FINDINGS_TO_FETCH,
    POSSIBLE_SEVERITIES,
    POSSIBLE_FINDING_CLASS_FILTERS,
    DEFAULT_SEVERITY,
    SEVERITY_FILTER_MAPPING
)
from UtilsManager import (
    datetime_to_rfc3339,
    convert_list_to_comma_string
)
from GoogleSecurityCommandCenterManager import GoogleSecurityCommandCenterManager
from SiemplifyConnectorsDataModel import AlertInfo
import sys
from EnvironmentCommon import GetEnvironmentCommonFactory


connector_starting_time = unix_now()
CONNECTOR_NAME = "Google Security Command Center - Findings Connector"


@output_handler
def main(is_test_run):
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = CONNECTOR_NAME
    processed_alerts = []

    if is_test_run:
        siemplify.LOGGER.info("***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******")

    siemplify.LOGGER.info("------------------- Main - Param Init -------------------")

    device_product_field = extract_connector_param(
        siemplify,
        param_name="DeviceProductField",
        default_value=DEFAULT_PRODUCT_FIELD_NAME,
        is_mandatory=True,
        print_value=True
    )

    environment_field_name = extract_connector_param(
        siemplify,
        default_value="",
        param_name="Environment Field Name",
        print_value=True
    )

    environment_regex_pattern = extract_connector_param(
        siemplify,
        param_name="Environment Regex Pattern",
        print_value=True
    )

    script_timeout = extract_connector_param(
        siemplify,
        param_name="PythonProcessTimeout",
        is_mandatory=True,
        input_type=int,
        print_value=True
    )

    api_root = extract_connector_param(
        siemplify,
        param_name="API Root",
        is_mandatory=True,
        print_value=True
    )

    organization_id = extract_connector_param(
        siemplify,
        param_name="Organization ID",
        is_mandatory=False,
        print_value=True
    )

    service_account_string = extract_connector_param(
        siemplify,
        param_name="User's Service Account",
        is_mandatory=True
    )

    finding_class_filter = extract_connector_param(
        siemplify,
        param_name="Finding Class Filter",
        default_value=convert_list_to_comma_string(POSSIBLE_FINDING_CLASS_FILTERS),
        input_type=str,
        print_value=True
    )

    lowest_severity_to_fetch = extract_connector_param(
        siemplify,
        param_name="Lowest Severity To Fetch",
        input_type=str,
        print_value=True
    )

    hours_backwards = extract_connector_param(
        siemplify,
        param_name="Max Hours Backwards",
        input_type=int,
        default_value=DEFAULT_MAX_HOURS_BACKWARDS,
        print_value=True
    )

    fetch_limit = extract_connector_param(
        siemplify,
        param_name="Max Findings To Fetch",
        input_type=int,
        default_value=DEFAULT_MAX_FINDINGS_TO_FETCH,
        print_value=True
    )

    whitelist_as_a_blacklist = extract_connector_param(
        siemplify,
        "Use dynamic list as a blacklist",
        is_mandatory=True,
        input_type=bool,
        print_value=True
    )

    verify_ssl = extract_connector_param(
        siemplify,
        param_name="Verify SSL",
        input_type=bool,
        print_value=True
    )

    whitelist_filter_type = BLACKLIST_FILTER if whitelist_as_a_blacklist else WHITELIST_FILTER
    whitelist = siemplify.whitelist if isinstance(siemplify.whitelist, list) else [siemplify.whitelist]

    try:
        siemplify.LOGGER.info("------------------- Main - Started -------------------")

        if hours_backwards < 0:
            siemplify.LOGGER.info(f"Max Hours Backwards must be greater than zero. "
                                  f"The default value {DEFAULT_MAX_HOURS_BACKWARDS} "
                                  f"will be used")
            hours_backwards = DEFAULT_MAX_HOURS_BACKWARDS

        if fetch_limit < 0:
            siemplify.LOGGER.info(f"Max Findings To Fetch must be greater than zero. The default value "
                                  f"{DEFAULT_MAX_FINDINGS_TO_FETCH} will be used")
            fetch_limit = DEFAULT_MAX_FINDINGS_TO_FETCH
        elif fetch_limit > 1000:
            siemplify.LOGGER.info(f"Max Findings To Fetch exceeded the maximum limit of 1000. "
                                  f"The default value {DEFAULT_MAX_FINDINGS_TO_FETCH} will be used")
            fetch_limit = DEFAULT_MAX_FINDINGS_TO_FETCH

        finding_class_filter_list = convert_comma_separated_to_list(finding_class_filter)

        if set(finding_class_filter_list).difference(set(POSSIBLE_FINDING_CLASS_FILTERS)):
            raise Exception(f"Invalid value provided for \"Finding Class Filter\" parameter. Possible values are: "
                            f"{convert_list_to_comma_string(POSSIBLE_FINDING_CLASS_FILTERS)}.")

        finding_class_filter_value = " OR ".join([f'findingClass="{f}"' for f in finding_class_filter_list])

        finding_class_filter = f'({finding_class_filter_value})'

        if not lowest_severity_to_fetch:
            siemplify.LOGGER.info(
                f"Parameter \"Lowest Severity To Fetch\" is empty. Findings with all severities "
                f"will be ingested"
            )
            severity_filter = SEVERITY_FILTER_MAPPING.get("SEVERITY_UNSPECIFIED")
        elif lowest_severity_to_fetch.upper() not in POSSIBLE_SEVERITIES:
            siemplify.LOGGER.info(
                f"Invalid value provided for \"Lowest Severity To Fetch\" parameter. Possible values are: "
                f"{convert_list_to_comma_string(POSSIBLE_SEVERITIES)}. "
                f"Default value {DEFAULT_SEVERITY} will be used.")
            severity_filter = SEVERITY_FILTER_MAPPING.get("MEDIUM")
        else:
            severity_filter = SEVERITY_FILTER_MAPPING.get(lowest_severity_to_fetch.upper())

        # Read already existing alerts ids
        existing_ids = read_ids(siemplify)
        siemplify.LOGGER.info(f"Successfully loaded {len(existing_ids)} existing ids")

        last_success_time = get_last_success_time(
            siemplify=siemplify,
            offset_with_metric={'hours': hours_backwards}
        )

        siemplify.LOGGER.info(f"Fetching attributes with timestamp greater than {last_success_time.isoformat()}")

        event_time_filter = f'eventTime >= "{datetime_to_rfc3339(last_success_time)}"'

        if whitelist_filter_type == WHITELIST_FILTER and whitelist:
            category_filter = " OR ".join([f'category="{rule_name}"' for rule_name in whitelist])
            category_filter = f" AND ({category_filter}) "
        elif whitelist_filter_type == BLACKLIST_FILTER and whitelist:
            category_filter = " AND ".join([f'category!="{rule_name}"' for rule_name in whitelist])
            category_filter = f" AND ({category_filter}) "
        else:
            category_filter = " "

        manager = GoogleSecurityCommandCenterManager(
            api_root=api_root,
            organization_id=organization_id,
            service_account_string=service_account_string,
            verify_ssl=verify_ssl,
            siemplify_logger=siemplify.LOGGER
        )
        manager.test_connectivity()

        fetched_alerts = []

        alerts = manager.get_alerts(
            finding_class_filter=finding_class_filter,
            category_filter=category_filter,
            severity_filter=severity_filter,
            event_time_filter=event_time_filter
        )

        siemplify.LOGGER.info(f"Fetched {len(alerts)} alerts")

        if is_test_run:
            siemplify.LOGGER.info("This is a TEST run. Only 1 alert will be processed.")
            alerts = alerts[:1]

        for alert in alerts:
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

                if not pass_whitelist_filter(siemplify, whitelist_as_a_blacklist, alert, "name"):
                    continue

                first_alert = alerts[0]
                alert_start_time = first_alert.start_time
                alert_end_time = first_alert.end_time

                siemplify.LOGGER.info(f"Started processing alert {alert.id}")

                # Check if already processed
                if alert.id in existing_ids:
                    siemplify.LOGGER.info(f"Alert {alert.id} skipped since it has been fetched before")
                    fetched_alerts.append(alert)
                    continue

                alert.start_time = alert_start_time
                alert.end_time = alert_end_time

                # Update existing alerts
                existing_ids.append(alert.id)
                fetched_alerts.append(alert)

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
            save_timestamp(siemplify=siemplify, alerts=fetched_alerts, timestamp_key="end_time")

    except Exception as e:
        siemplify.LOGGER.error(f"Got exception on main handler. Error: {e}")
        siemplify.LOGGER.exception(e)

        if is_test_run:
            raise

    siemplify.LOGGER.info(f"Created total of {len(processed_alerts)} cases")
    siemplify.LOGGER.info("------------------- Main - Finished -------------------")
    siemplify.return_package(processed_alerts)


if __name__ == "__main__":
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == "True")
    main(is_test)

