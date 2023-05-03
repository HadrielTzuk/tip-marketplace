import sys
import uuid
from constants import TIMEOUT_THRESHOLD, DEFAULT_DEVICE_PRODUCT, DEFAULT_DEVICE_VENDOR, DETECTION_CONNECTOR_NAME, \
    SEVERITIES, DEFAULT_PADDING_PERIOD, MAX_PADDING_PERIOD
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import output_handler, unix_now, convert_string_to_unix_time
from TIPCommon import extract_connector_param, dict_to_flat, is_overflowed, save_timestamp, read_ids, write_ids, \
    filter_old_alerts, get_last_success_time, UNIX_FORMAT
from EnvironmentCommon import GetEnvironmentCommonFactory
from CrowdStrikeManager import CrowdStrikeManager
from utils import is_approaching_timeout, convert_list_to_comma_string, convert_hours_to_milliseconds, \
    convert_unix_time_to_datetime


DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S"


@output_handler
def main(is_test_run):
    processed_detections = []
    all_detections = []
    existing_ids = []
    connector_starting_time = unix_now()
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = DETECTION_CONNECTOR_NAME

    if is_test_run:
        siemplify.LOGGER.info('***** This is an \'IDE Play Button\' \'Run Connector once\' test run ******')

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    environment_field_name = extract_connector_param(
        siemplify,
        param_name='Environment Field Name',
        print_value=True
    )

    environment_regex_pattern = extract_connector_param(
        siemplify,
        param_name='Environment Regex Pattern',
        print_value=True
    )

    api_root = extract_connector_param(
        siemplify,
        param_name='API Root',
        is_mandatory=True,
        print_value=True
    )

    client_id = extract_connector_param(
        siemplify,
        param_name='Client ID',
        is_mandatory=True,
    )

    client_secret = extract_connector_param(
        siemplify,
        param_name='Client Secret',
        is_mandatory=True,
    )

    lowest_severity = extract_connector_param(
        siemplify,
        param_name='Lowest Severity Score To Fetch',
        print_value=True
    )

    lowest_confidence = extract_connector_param(
        siemplify,
        param_name='Lowest Confidence Score To Fetch',
        input_type=int,
        print_value=True
    )

    max_hours_backwards = extract_connector_param(
        siemplify,
        param_name='Max Hours Backwards',
        input_type=int,
        default_value=0,
        print_value=True
    )

    max_detections_to_fetch = extract_connector_param(
        siemplify,
        param_name='Max Detections To Fetch',
        input_type=int,
        default_value=10,
        print_value=True
    )

    python_process_timeout = extract_connector_param(
        siemplify,
        param_name="PythonProcessTimeout",
        input_type=int,
        is_mandatory=True,
        print_value=True
    )

    verify_ssl = extract_connector_param(
        siemplify,
        param_name='Verify SSL',
        input_type=bool,
        default_value=False,
        is_mandatory=True,
        print_value=True
    )

    padding_period = extract_connector_param(
        siemplify,
        param_name="Padding Period",
        input_type=int,
        print_value=True
    )

    siemplify.LOGGER.info('------------------- Main - Started -------------------')
    whitelist = siemplify.whitelist if isinstance(siemplify.whitelist, list) else [siemplify.whitelist]

    environment_common = GetEnvironmentCommonFactory.create_environment_manager(
        siemplify, environment_field_name, environment_regex_pattern)

    try:
        if lowest_severity:
            try:
                lowest_severity = int(lowest_severity)
                if lowest_severity < 0 or lowest_severity > 100:
                    raise Exception(
                        f"invalid int value provided for the parameter \"Lowest Severity Score To Fetch\". "
                        f"Supported values are in range 0 to 100.")
            except ValueError:
                if lowest_severity.title() not in SEVERITIES:
                    raise Exception(f"Invalid value provided for the parameter \"Lowest Severity Score To Fetch\". "
                                    f"Supported values: "
                                    f"{convert_list_to_comma_string([severity.title() for severity in SEVERITIES])}.")

        if lowest_confidence and (lowest_confidence < 0 or lowest_confidence > 100):
            raise Exception(
                f"invalid int value provided for the parameter \"Lowest Confidence Score To Fetch\". "
                f"Supported values are in range 0 to 100.")

        if padding_period is not None and (padding_period < 0 or padding_period > MAX_PADDING_PERIOD):
            siemplify.LOGGER.info(f"\"Padding Period\" must be non-negative and maximum is {MAX_PADDING_PERIOD} hours. "
                                  f"The default value {DEFAULT_PADDING_PERIOD} will be used")
            padding_period = DEFAULT_PADDING_PERIOD

        last_success_time = get_last_success_time(siemplify=siemplify,
                                                  offset_with_metric={"hours": max_hours_backwards},
                                                  time_format=UNIX_FORMAT)

        if padding_period and last_success_time > unix_now() - convert_hours_to_milliseconds(padding_period):
            last_success_time = unix_now() - convert_hours_to_milliseconds(padding_period)
            siemplify.LOGGER.info(f"Last success time is greater than alerts padding period. Unix: {last_success_time} "
                                  f"will be used as last success time")

        manager = CrowdStrikeManager(
            client_id=client_id,
            client_secret=client_secret,
            use_ssl=verify_ssl,
            api_root=api_root,
            logger=siemplify.LOGGER
        )
        # Read already existing alerts ids
        siemplify.LOGGER.info('Reading already existing alerts ids...')
        existing_ids = read_ids(siemplify)
        detections = manager.get_detections_connector(first_behavior=convert_unix_time_to_datetime(last_success_time),
                                                      severity=lowest_severity, confidence=lowest_confidence,
                                                      limit=max_detections_to_fetch, filters=whitelist)

        filtered_detections = filter_old_alerts(siemplify, detections, existing_ids, 'detection_id')

        siemplify.LOGGER.info('Alert to process after filtering already processed once {} out of {} '
                              'received from the API'.format(len(filtered_detections), len(detections)))

        for detection in filtered_detections:
            try:
                if is_approaching_timeout(python_process_timeout, connector_starting_time, TIMEOUT_THRESHOLD):
                    siemplify.LOGGER.info('Timeout is approaching. Connector will gracefully exit')
                    break

                if is_test_run and processed_detections:
                    siemplify.LOGGER.info('Maximum detections count (1) for test run reached!')
                    break

                if len(processed_detections) >= max_detections_to_fetch:
                    # Provide slicing for the alerts amount.
                    siemplify.LOGGER.info(
                        "Reached max number of alerts cycle. No more alerts will be processed in this cycle."
                    )
                    break

                all_detections.append(detection)

                siemplify.LOGGER.info('Starting detection with id: {}'.format(detection.detection_id))

                siemplify.LOGGER.info('Processing detection with id: {}'.format(detection.detection_id))
                alert_info = create_alert_info(siemplify, environment_common, detection)

                if is_overflowed(siemplify, alert_info, is_test_run):
                    siemplify.LOGGER.info(
                        '{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping.'
                            .format(alert_name=alert_info.rule_generator,
                                    alert_identifier=alert_info.ticket_id,
                                    environment=alert_info.environment,
                                    product=alert_info.device_product))
                    # If is overflowed we should skip
                    continue

                processed_detections.append(alert_info)
                siemplify.LOGGER.info('Detection with id {} was created.'.format(detection.detection_id))

            except Exception as e:
                siemplify.LOGGER.error('Failed to process detection with id {}'.format(detection.detection_id))
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise
    except Exception as e:
        siemplify.LOGGER.error(f'Error executing connector: \"Detection Connector\". Reason: {e}')
        siemplify.LOGGER.exception(e)

        if is_test_run:
            raise

    if not is_test_run and all_detections:
        siemplify.LOGGER.info("Saving existing ids.")
        write_ids(siemplify, existing_ids + [detection.detection_id for detection in all_detections])
        save_timestamp(siemplify=siemplify, alerts=all_detections, timestamp_key='first_behavior_timestamp')

    siemplify.LOGGER.info('Detections processed: {} out of {}'.format(len(processed_detections), len(all_detections)))
    siemplify.LOGGER.info('Created total of {} alerts'.format(len(processed_detections)))

    siemplify.LOGGER.info('------------------- Main - Finished -------------------')
    siemplify.return_package(processed_detections)


def create_alert_info(siemplify, environment_common, detection):
    siemplify.LOGGER.info('Creating alert info for detection {}'.format(detection.detection_id))

    alert_info = AlertInfo()
    alert_info.ticket_id = detection.detection_id
    alert_info.display_id = str(uuid.uuid4())
    alert_info.name = alert_info.rule_generator = detection.alert_name.capitalize()
    alert_info.device_vendor = DEFAULT_DEVICE_VENDOR
    alert_info.device_product = DEFAULT_DEVICE_PRODUCT
    alert_info.priority = detection.severity
    alert_info.start_time = convert_string_to_unix_time(detection.first_behavior)
    alert_info.end_time = convert_string_to_unix_time(detection.last_behavior)
    alert_info.environment = environment_common.get_environment(dict_to_flat(detection.to_json()))
    alert_info.events = detection.to_events()

    siemplify.LOGGER.info('Alert info created for detection {}'.format(detection.detection_id))

    return alert_info


if __name__ == '__main__':
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test)
