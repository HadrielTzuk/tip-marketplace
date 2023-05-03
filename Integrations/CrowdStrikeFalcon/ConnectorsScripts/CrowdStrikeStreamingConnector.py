import sys
import uuid

from CrowdStrikeManager import CrowdStrikeManager
from EnvironmentCommon import GetEnvironmentCommonFactory
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyUtils import (
    output_handler,
    convert_unixtime_to_datetime,
    convert_string_to_unix_time,
    unix_now,
)
from TIPCommon import extract_connector_param, is_overflowed, string_to_multi_value
from constants import (
    SIEM_UNKNOWN_EVENT_TYPE,
    EVENT_STREAMING_CONNECTOR_NAME,
    API_ROOT_DEFAULT,
    SIEMPLIFY_PREFIX_FOR_APP,
)
from exceptions import CrowdStrikeStreamError
from utils import (
    get_formatted_last_success_time,
    get_offset,
    store_offset,
    is_approaching_timeout,
)

DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
connector_starting_time = unix_now()


@output_handler
def main(is_test_run: bool) -> None:
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = EVENT_STREAMING_CONNECTOR_NAME
    processed_alerts, all_alerts = [], []

    if is_test_run:
        siemplify.LOGGER.info(
            "***** This is an 'IDE Play Button' 'Run Connector once' test run ******"
        )

    siemplify.LOGGER.info("------------------- Main - Param Init -------------------")

    python_process_timeout = extract_connector_param(
        siemplify,
        param_name="PythonProcessTimeout",
        input_type=int,
        is_mandatory=True,
        print_value=True,
    )

    environment = extract_connector_param(
        siemplify, param_name="Environment Field Name", print_value=True
    )
    environment_regex = extract_connector_param(
        siemplify, param_name="Environment Regex Pattern", print_value=True
    )

    api_root = extract_connector_param(
        siemplify,
        param_name="API Root",
        print_value=True,
        default_value=API_ROOT_DEFAULT,
    )
    client_id = extract_connector_param(
        siemplify, param_name="Client ID", is_mandatory=True
    )
    client_secret = extract_connector_param(
        siemplify, param_name="Client Secret", is_mandatory=True
    )

    event_types = string_to_multi_value(
        extract_connector_param(siemplify, param_name="Event types", print_value=True)
    )

    limit = extract_connector_param(
        siemplify,
        param_name="Max Events per Cycle",
        input_type=int,
        is_mandatory=True,
        print_value=True,
    )
    limit = 1 if is_test_run else limit

    max_days_backwards = extract_connector_param(
        siemplify, param_name="Max Day Backwards", input_type=int, print_value=True
    )
    min_severity = extract_connector_param(
        siemplify, param_name="Min Severity", input_type=int, print_value=True
    )

    verify_ssl = extract_connector_param(
        siemplify, param_name="Verify SSL", input_type=bool, print_value=True
    )
    app_name = f"{SIEMPLIFY_PREFIX_FOR_APP}{str(uuid.uuid4()).replace('-', '')}"[:30]

    alert_name_template = extract_connector_param(
        siemplify, param_name="Alert Name Template", print_value=True
    )
    rule_generator_template = extract_connector_param(
        siemplify, param_name="Rule Generator Template", print_value=True
    )

    siemplify.LOGGER.info("------------------- Main - Started -------------------")

    if not event_types:
        siemplify.LOGGER.info(
            "\"Event types\" parameter were not provided. All event types will be ingested"
        )

    try:
        environment_common = GetEnvironmentCommonFactory.create_environment_manager(
            siemplify, environment, environment_regex
        )

        last_success_time = get_formatted_last_success_time(
            siemplify=siemplify,
            offset_with_metric={"days": max_days_backwards},
            date_time_format=DATETIME_FORMAT,
        )

        offset = 0 if is_test_run else get_offset(siemplify)
        siemplify.LOGGER.info(f"Current offset is {offset}")

        manager = CrowdStrikeManager(
            client_id=client_id,
            client_secret=client_secret,
            use_ssl=verify_ssl,
            api_root=api_root,
            logger=siemplify.LOGGER,
        )

        for detection in manager.get_stream_detections(app_name, offset, limit):
            try:
                if is_approaching_timeout(
                    python_process_timeout, connector_starting_time
                ):
                    siemplify.LOGGER.info(
                        "Timeout is approaching. Connector will gracefully exit"
                    )
                    break

                all_alerts.append(detection)

                siemplify.LOGGER.info(
                    f"Starting detection with offset: {detection.offset} and event type: "
                    f"{detection.event_type}"
                )

                if (
                    min_severity
                    and detection.is_detection
                    and detection.severity < min_severity
                ):
                    siemplify.LOGGER.info(
                        f"Skipping detection with severity {detection.severity} which is less "
                        f"than {min_severity}"
                    )
                    continue

                siemplify.LOGGER.info(
                    f"Create Time: {convert_unixtime_to_datetime(detection.event_creation_time).isoformat()}"
                )

                if event_types:
                    # To not cause regressions, we continue supporting "UserActivity",
                    # "Detection", "AuthActivity" and "Remote" event types
                    if (
                        not (
                            detection.type in event_types
                            and detection.type != SIEM_UNKNOWN_EVENT_TYPE
                        )
                    ) and (
                        detection.event_type and detection.event_type not in event_types
                    ):
                        siemplify.LOGGER.info(
                            f"Skipping detection with event type {detection.event_type} which is "
                            f"not in provided event types: {', '.join(event_types)}"
                        )
                        continue

                if last_success_time and not detection.has_creation_time_newer_than(
                    convert_string_to_unix_time(last_success_time)
                ):
                    siemplify.LOGGER.info(
                        f"Skipping detection with event creation time {detection.event_creation_time} "
                        f"which is older than minimum event creation time {last_success_time} "
                        f"calculated with max days backwards {max_days_backwards}"
                    )
                    continue

                if detection.is_api_stream_action(client_id, SIEMPLIFY_PREFIX_FOR_APP):
                    siemplify.LOGGER.info(
                        f"Skipping detection with offset {detection.offset} made by stream "
                        f"connector with App ID {app_name}"
                    )
                    continue

                siemplify.LOGGER.info(
                    f"Processing detection with offset {detection.offset}"
                )
                alert_info = detection.get_alert_info(
                    environment_common, alert_name_template, rule_generator_template
                )

                if is_overflowed(siemplify, alert_info, is_test_run):
                    siemplify.LOGGER.info(
                        f"{alert_info.rule_generator}-"
                        f"{alert_info.ticket_id}-"
                        f"{alert_info.environment}-"
                        f"{alert_info.device_product} found as overflow alert. Skipping."
                    )
                    # If is overflowed we should skip
                    continue

                processed_alerts.append(alert_info)
                siemplify.LOGGER.info(
                    f"Detection with offset {detection.offset} was created."
                )

            except Exception as error:
                siemplify.LOGGER.error(
                    f"Failed to process detection with offset {detection.offset}"
                )
                siemplify.LOGGER.exception(error)

                if is_test_run:
                    raise

    except CrowdStrikeStreamError as error:
        siemplify.LOGGER.info(error)

    except Exception as err:
        siemplify.LOGGER.error(f"Got exception on main handler. Error: {err}")
        siemplify.LOGGER.exception(err)
        if is_test_run:
            raise

    if not is_test_run and all_alerts:
        last_offset = sorted(all_alerts, key=lambda det: det.offset)[-1].offset
        # increment offset to avoid duplication
        offset_to_store = last_offset + 1
        store_offset(siemplify, offset_to_store)

        siemplify.LOGGER.info(f"New offset {offset_to_store} stored")

    siemplify.LOGGER.info(
        f"Detections processed: {len(processed_alerts)} of {len(all_alerts)}"
    )
    siemplify.LOGGER.info(f"Created total of {len(processed_alerts)} cases")
    siemplify.LOGGER.info("------------------- Main - Finished -------------------")
    siemplify.return_package(processed_alerts)


if __name__ == "__main__":
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == "True")
    main(is_test_run)
