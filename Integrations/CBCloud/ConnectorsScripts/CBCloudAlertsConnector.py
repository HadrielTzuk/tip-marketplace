from SiemplifyUtils import output_handler
import sys
import arrow
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import AlertInfo
from EnvironmentCommon import GetEnvironmentCommonFactory
from CBCloudManager import CBCloudManager
from TIPCommon import extract_connector_param, read_ids_by_timestamp, write_ids_with_timestamp, save_timestamp, \
    siemplify_fetch_timestamp, validate_timestamp, filter_old_ids
from exceptions import CBCloudConnectorValidationException
from constants import DEFAULT_VENDOR, PROVIDER_NAME, ALERTS_CONNECTOR_NAME

TIMESTAMP_FILE = "timestamp.stmp"
MAP_FILE = 'map.json'
IDS_FILE = 'ids.json'
WHITELIST_FILTER = 'whitelist'
BLACKLIST_FILTER = 'blacklist'
VALIDATOR_FIELDS = ["type", "category", "policy_name"]


@output_handler
def main(is_test_run):
    alerts = []
    all_alerts = []
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = ALERTS_CONNECTOR_NAME

    if is_test_run:
        siemplify.LOGGER.info("***** This is an \"IDE Play Button\" \"Run Connector once\" test run ******")

    siemplify.LOGGER.info("==================== Main - Param Init ====================")

    environment = extract_connector_param(
        siemplify,
        param_name='Environment Field Name',
        print_value=True
    )

    environment_regex = extract_connector_param(
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

    org_key = extract_connector_param(
        siemplify,
        param_name='Organization Key',
        is_mandatory=True,
        print_value=True
    )

    api_id = extract_connector_param(
        siemplify,
        param_name='API ID',
        is_mandatory=True,
    )

    api_secret_key = extract_connector_param(
        siemplify,
        param_name='API Secret Key',
        is_mandatory=True,
    )

    verify_ssl = extract_connector_param(
        siemplify,
        param_name='Verify SSL',
        input_type=bool,
        print_value=True
    )

    offset_in_hours = extract_connector_param(
        siemplify,
        param_name='Offset Time In Hours',
        input_type=int,
        is_mandatory=True,
        print_value=True
    )

    max_alerts_per_cycle = extract_connector_param(
        siemplify,
        param_name='Max Alerts Per Cycle',
        input_type=int,
        is_mandatory=True,
        print_value=True
    )

    min_severity = extract_connector_param(
        siemplify,
        param_name='Minimum Severity to Fetch',
        print_value=True
    )

    alert_name_field_name = extract_connector_param(
        siemplify,
        param_name="What Alert Field to use for Name field",
        is_mandatory=True,
        print_value=True
    )

    rule_generator_field_name = extract_connector_param(
        siemplify,
        param_name="What Alert Field to use for Rule Generator",
        is_mandatory=True,
        print_value=True
    )

    whitelist_as_a_blacklist = extract_connector_param(
        siemplify,
        param_name='Use whitelist as a blacklist',
        is_mandatory=True,
        input_type=bool,
        print_value=True
    )
    whitelist_filter_type = BLACKLIST_FILTER if whitelist_as_a_blacklist else WHITELIST_FILTER
    whitelist = siemplify.whitelist

    validate_alert_name_field_name(alert_name_field_name)
    validate_rule_generator_field_name(rule_generator_field_name)

    siemplify.LOGGER.info("------------------- Main - Started -------------------")

    environment_common = GetEnvironmentCommonFactory.create_environment_manager(siemplify, environment,
                                                                                environment_regex, MAP_FILE)
    if is_test_run:
        siemplify.LOGGER.info("This is a test run. Ignoring stored timestamps.")
        last_success_time_datetime = arrow.utcnow().shift(hours=-offset_in_hours).datetime
    else:
        last_success_time_datetime = validate_timestamp(
            siemplify_fetch_timestamp(siemplify, datetime_format=True), offset_in_hours
        )

    now = arrow.utcnow()

    existing_ids = read_ids_by_timestamp(siemplify, offset_in_hours=max(72, 2 * offset_in_hours))

    manager = CBCloudManager(api_root=api_root, org_key=org_key, api_id=api_id, api_secret_key=api_secret_key,
                             verify_ssl=verify_ssl)

    if min_severity:
        siemplify.LOGGER.info("Fetching alerts from {} to {} with min. severity of {}".format(
            last_success_time_datetime.strftime("%Y-%m-%d %H:%M:%SZ"),
            now.isoformat(),
            min_severity
        ))
    else:
        siemplify.LOGGER.info("Fetching alerts from {} to {}".format(
            last_success_time_datetime.isoformat(),
            now.isoformat()
        ))

    fetched_alerts = manager.get_alerts(
        start_time=last_success_time_datetime.isoformat(),
        end_time=now.isoformat(),
        min_severity=min_severity,
        workflows=["OPEN"],
        limit=max(max_alerts_per_cycle, 100),
        sort_by="create_time",
        categories=whitelist if whitelist_filter_type == WHITELIST_FILTER else None
    )

    filtered_ids = filter_old_ids([alert.id for alert in fetched_alerts], existing_ids)
    filtered_alerts = [alert for alert in fetched_alerts if alert.id in filtered_ids]

    siemplify.LOGGER.info(
        "Found {} new alert in since {}.".format(len(filtered_alerts), last_success_time_datetime.isoformat())
    )

    if is_test_run:
        siemplify.LOGGER.info("This is a TEST run. Only 1 alert will be processed.")
        filtered_alerts = filtered_alerts[:1]

    filtered_alerts = sorted(filtered_alerts, key=lambda alert: alert.create_time_ms)

    if len(filtered_alerts) > max_alerts_per_cycle:
        filtered_alerts = filtered_alerts[:max_alerts_per_cycle]
        siemplify.LOGGER.info("Slicing to {} alerts".format(max_alerts_per_cycle))

    for alert in filtered_alerts:
        try:

            is_overflowed = False
            siemplify.LOGGER.info("Processing alert {}".format(alert.id))
            alert_info = create_alert_info(environment_common, alert, alert_name_field_name, rule_generator_field_name)
            existing_ids.update({alert.id: alert.create_time})
            all_alerts.append(alert_info)

            if not pass_whitelist_filter(siemplify, alert, whitelist, whitelist_filter_type):
                siemplify.LOGGER.info('Alert {} did not pass filters skipping....'.format(alert.id))
                continue

            try:
                is_overflowed = siemplify.is_overflowed_alert(
                    environment=alert_info.environment,
                    alert_identifier=alert_info.ticket_id,
                    alert_name=alert_info.rule_generator,
                    product=alert_info.device_product
                )

            except Exception as e:
                siemplify.LOGGER.error('Error validation connector overflow, ERROR: {}'.format(e))
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            if is_overflowed:
                siemplify.LOGGER.info(
                    "{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping."
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
                siemplify.LOGGER.info('Alert {} was created.'.format(alert.id))

        except Exception as e:
            siemplify.LOGGER.error("Failed to process alert {}".format(alert.id), alert_id=alert.id)
            siemplify.LOGGER.exception(e)

            if is_test_run:
                raise

    if not is_test_run:
        if all_alerts:
            save_timestamp(siemplify, all_alerts, timestamp_key='start_time')
        write_ids_with_timestamp(siemplify, existing_ids)

    siemplify.LOGGER.info("Created total of {} alerts".format(len(alerts)))

    siemplify.LOGGER.info("------------------- Main - Finished -------------------")
    siemplify.return_package(alerts)


def validate_alert_name_field_name(alert_name_field_name):
    """
    Validate the value passed to the Name Field of Siemplify Alert configuration
    :return: {bool} True if valid, exception otherwise
    """
    if alert_name_field_name not in VALIDATOR_FIELDS:
        raise CBCloudConnectorValidationException(
            "Valid values to use for the \"What Alert Field to use for Name field\" are type, category or policy_name"
        )

    return True


def validate_rule_generator_field_name(rule_generator_field_name):
    """
    Validate the value passed to the Rule Generator Field of Siemplify Alert configuration
    :return: {bool} True if valid, exception otherwise
    """
    if rule_generator_field_name not in VALIDATOR_FIELDS:
        raise CBCloudConnectorValidationException(
            "Valid values to use for the \"What Alert Field to use for Rule Generator\" are type, category or policy_name"
        )

    return True


def create_alert_info(environment_common, alert, alert_name_field_name, rule_generator_field_name):
    """
    Create an AlertInfo object from a single alert
    :param environment_common: {EnvironmentHandle}
    :param alert: {Alert} An alert instance
    :param alert_name_field_name: {unicode} The field name to take the alert name from
    :param rule_generator_field_name: {unicode} The field name to take the rule generator value from
    :return: {AlertInfo} The created alert info object
    """
    alert_info = AlertInfo()
    alert_info.start_time = alert.create_time_ms
    alert_info.end_time = alert.last_update_time_ms
    alert_info.ticket_id = alert.id
    alert_info.display_id = alert.id
    alert_info.name = f"CBCLOUD_Alert_{getattr(alert, alert_name_field_name)}"
    alert_info.rule_generator = f"CBCLOUD_{getattr(alert, rule_generator_field_name)}"
    alert_info.priority = alert.priority
    alert_info.description = alert.reason
    alert_info.device_product = PROVIDER_NAME
    alert_info.device_vendor = DEFAULT_VENDOR
    alert_info.environment = environment_common.get_environment(alert.as_json())
    alert_info.source_grouping_identifier = alert.threat_id
    alert_info.events = [alert.as_event()]
    alert_info.extensions = {
        "id": alert.id,
        "legacy_alert_id": alert.legacy_alert_id
    }

    return alert_info


def pass_whitelist_filter(siemplify, alert, whitelist, whitelist_filter_type):
    # whitelist filter
    if whitelist:
        if whitelist_filter_type == BLACKLIST_FILTER and alert.category in whitelist:
            siemplify.LOGGER.info("Alert with category {} did not pass blacklist filter.".format(alert.category))
            return False

    return True


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == 'True':
        print("Main execution started")
        main(is_test_run=False)
    else:
        print("Test execution started")
        main(is_test_run=True)
