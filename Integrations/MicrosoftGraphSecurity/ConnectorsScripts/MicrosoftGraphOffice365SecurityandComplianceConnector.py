import sys
import uuid

from datetime import timedelta, datetime
from SiemplifyConnectors import SiemplifyConnectorExecution, CaseInfo
from SiemplifyUtils import output_handler, utc_now
from MicrosoftGraphSecurityManager import MicrosoftGraphSecurityManager
from EnvironmentCommon import GetEnvironmentCommonFactory
from TIPCommon import (
    extract_connector_param,
    dict_to_flat,
    read_ids,
    write_ids,
    convert_comma_separated_to_list,
    validate_timestamp,
    is_overflowed
)


CONNECTOR_NAME = "Microsoft Graph Alerts"
VENDOR = "Microsoft"

EVENT_STATES = ["fileStates", "hostStates", "malwareStates",
                "networkConnections", "registryKeyStates", "triggers",
                "userStates", "vulnerabilityStates", "cloudAppStates",
                "processes", ]

STATUSES_MAPPING = {
    'dismissed': 'dismissed',
    'investigating': 'inProgress',
    'active': 'newAlert',
    'resolved': 'resolved'
}
API_TO_UI_STATUSES_MAPPING = {
    'dismissed': 'Dismissed',
    'inProgress': 'Investigating',
    'newAlert': 'Active',
    'resolved': 'Resolved'
}

SEVERITIES = 'high, medium, low, informational, unknown'
SCRIPT_TIMEOUT_SECONDS = 30
MAX_ALERTS = 50
OFFSET_TIME_HOURS = 120
ALERT_NAME = 'UNABLE TO GET ALERT NAME'
ALERT_RULE_GENERATOR = 'UNABLE TO GET ALERT RULE GENERATOR'
MAP_FILE = "map.json"
O365_PROVIDER_NAME = 'Office 365 Security and Compliance'


def create_alert_info(siemplify, environment_common, alert):
    alert_info = CaseInfo()

    if alert.id:
        alert_id = alert.id
    else:
        alert_id = str(uuid.uuid4())
        siemplify.LOGGER.info(f'Alert ID does not found, use generated uuid {alert_id} instead')

    alert_info.display_id = alert_id
    alert_info.ticket_id = alert_id
    alert_info.name = alert.title or ALERT_NAME
    alert_info.device_vendor = alert.vendor
    alert_info.device_product = alert.provider
    alert_info.priority = alert.siemplify_severity
    alert_info.rule_generator = alert.category or ALERT_RULE_GENERATOR
    alert_info.start_time = alert.created_datetime_ms
    alert_info.end_time = alert.last_modified_datetime_ms
    alert_info.extensions.update(alert.as_extension())

    alert_info.events = [alert.as_event()]

    # Use nested State objects as Events
    for state in EVENT_STATES:
        for event in alert.raw_data.get(state, []):
            try:
                flattened_event = dict_to_flat(event)
                flattened_event['event_class'] = state
                flattened_event['alert_id'] = alert_id
                flattened_event['timestamp'] = alert_info.start_time
                if flattened_event.get('createdDateTime'):
                    flattened_event['iso_timestamp'] = flattened_event.get('createdDateTime')
                elif flattened_event.get('timestamp'):
                    _dt = datetime.fromtimestamp(int(flattened_event.get('timestamp')) / 1000)
                    flattened_event['iso_timestamp'] = _dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                alert_info.events.append(flattened_event)
            except Exception as e:
                siemplify.LOGGER.error("Failed to build event {}".format(event))
                siemplify.LOGGER.exception(e)

    if not alert_info.events:
        siemplify.LOGGER.info(f"No events found for Alert {alert_id}")

    alert_info.environment = environment_common.get_environment(alert.raw_data)
    siemplify.LOGGER.info(f"-------------- Finished processing Alert {alert_id}", alert_id=alert_id)

    return alert_info


@output_handler
def main(is_test_run):
    alerts = []
    all_alerts = []
    siemplify = SiemplifyConnectorExecution()  # Siemplify main SDK wrapper
    siemplify.script_name = CONNECTOR_NAME

    siemplify.LOGGER.info("==================== Main - Param Init ====================")

    environment_field_name = extract_connector_param(
        siemplify,
        'Environment Field Name',
        default_value='',
        input_type=str,
        is_mandatory=False,
        print_value=True
    )

    environment_regex_pattern = extract_connector_param(
        siemplify,
        'Environment Regex Pattern',
        default_value='.*',
        input_type=str,
        is_mandatory=False,
        print_value=True
    )

    client_id = extract_connector_param(
        siemplify,
        'Client ID',
        default_value='',
        input_type=str,
        is_mandatory=True,
        print_value=False
    )

    secret_id = extract_connector_param(
        siemplify,
        'Client Secret',
        default_value='',
        input_type=str,
        is_mandatory=False,
        print_value=False
    )

    certificate_path = extract_connector_param(
        siemplify,
        'Certificate Path',
        default_value='',
        input_type=str,
        is_mandatory=False,
        print_value=False
    )

    certificate_password = extract_connector_param(
        siemplify,
        'Certificate Password',
        default_value='',
        input_type=str,
        is_mandatory=False,
        print_value=False
    )

    azure_active_directory_id = extract_connector_param(
        siemplify,
        'Azure Active Directory ID',
        default_value='',
        input_type=str,
        is_mandatory=True,
        print_value=True
    )

    verify_ssl = extract_connector_param(
        siemplify,
        param_name='Verify SSL',
        default_value=True,
        input_type=bool,
        is_mandatory=True
    )

    offset_time_hours = extract_connector_param(
        siemplify,
        'Offset Time In Hours',
        default_value=OFFSET_TIME_HOURS,
        input_type=int,
        is_mandatory=True,
        print_value=True
    )

    alert_statuses_to_fetch = extract_connector_param(
        siemplify,
        'Alert Statuses to fetch',
        input_type=str,
        is_mandatory=False,
        print_value=True
    )

    alert_severities_to_fetch = extract_connector_param(
        siemplify,
        'Alert Severities to fetch',
        input_type=str,
        is_mandatory=False,
        print_value=True
    )

    max_alerts_per_cycle = extract_connector_param(
        siemplify,
        'Max Alerts Per Cycle',
        default_value=MAX_ALERTS,
        input_type=int,
        is_mandatory=True,
        print_value=True
    )

    provider_list = [O365_PROVIDER_NAME]
    last_run_time = siemplify.fetch_timestamp(datetime_format=True)
    environment_common = GetEnvironmentCommonFactory.create_environment_manager(
        siemplify, environment_field_name, environment_regex_pattern
    )

    # Read already existing alerts ids
    siemplify.LOGGER.info('Reading already existing alerts ids...')
    existing_ids = read_ids(siemplify)

    # Ignore stored timestamp when running tests
    if is_test_run:
        siemplify.LOGGER.info("This is a test run. Ignoring stored timestamps")
        last_calculated_run_time = validate_timestamp(utc_now() - timedelta(hours=offset_time_hours), offset_time_hours)
    else:
        last_calculated_run_time = validate_timestamp(last_run_time, offset_time_hours)

    try:
        mtm = MicrosoftGraphSecurityManager(client_id, secret_id, certificate_path, certificate_password,
                                            azure_active_directory_id, verify_ssl=verify_ssl, siemplify=siemplify)
    except Exception as e:
        siemplify.LOGGER.error("Could not authenticate against Microsoft Graph Security. Check Credentials")
        siemplify.LOGGER.exception(e)
        raise

    siemplify.LOGGER.info("------------------- Main - Started -------------------")

    if is_test_run:
        siemplify.LOGGER.info("This is a TEST run. Only 1 alert will be processed.")
        max_alerts_per_cycle = 1
    else:
        siemplify.LOGGER.info('Slicing alerts to {}'.format(max_alerts_per_cycle))

    fetched_alerts = mtm.list_alerts(
        provider_list=provider_list,
        severity_list=None,
        status_list=None,
        start_time=last_calculated_run_time,
        max_alerts=max_alerts_per_cycle,
        existing_ids=existing_ids
    )

    siemplify.LOGGER.info('Found {} alerts'.format(len(fetched_alerts)))

    for alert in fetched_alerts:
        try:
            siemplify.LOGGER.info('Started processing Alert {} - {}'.format(alert.id, alert.title or ALERT_NAME),
                                  alert_id=alert.id)
            # Update existing alerts
            existing_ids.append(alert.id)

            if not pass_severity_filter(siemplify, alert, alert_severities_to_fetch):
                siemplify.LOGGER.info(
                    'Alert {} did not pass severity filter. Skipping....'.format(alert.id))
                continue

            if not pass_status_filter(siemplify, alert, alert_statuses_to_fetch or []):
                siemplify.LOGGER.info(
                    'Alert {} did not pass status filter. Skipping....'.format(alert.id))
                continue

            alert_info = create_alert_info(siemplify, environment_common, alert)

            overflowed = is_overflowed(siemplify, alert_info, is_test_run)
            if overflowed and not is_test_run:
                siemplify.LOGGER.info("Alert {} is overflow. Skipping".format(alert.id))
                continue

            else:
                siemplify.LOGGER.info("Alert: '{}' Created in Graph at {}".format(alert.id, alert.created_datetime))

            if not overflowed:
                alerts.append(alert_info)

            all_alerts.append(alert_info)

        except Exception as e:
            siemplify.LOGGER.error(
                "Could not add alert '{}' ({}) to Siemplify. Skipping.".format(alert.title, alert.id))
            siemplify.LOGGER.exception("Exception raised: {}".format(e))

            if is_test_run:
                raise

    if not is_test_run:
        if all_alerts:
            all_alerts = sorted(all_alerts, key=lambda alert: alert.start_time)
            # The timestamps are in milliseconds
            # So increase the last found timestamp by 1 millisecond to proceed to the next millisecond
            siemplify.save_timestamp(new_timestamp=all_alerts[-1].start_time + 1)

        write_ids(siemplify, existing_ids)

    siemplify.LOGGER.info("Alerts Processed: {} of {}".format(len(alerts), len(all_alerts)))
    siemplify.LOGGER.info("Created total of {} alerts".format(len(alerts)))

    siemplify.LOGGER.info("------------------- Main - Finished -------------------")
    siemplify.return_package(alerts)


def pass_severity_filter(siemplify, alert, severity_filter):
    # severity filter
    if severity_filter and alert.severity not in convert_comma_separated_to_list(severity_filter):
        siemplify.LOGGER.info('Alert with severity: {} did not pass filter. Acceptable severities are: {}.'.
                              format(alert.severity, severity_filter))
        return False
    return True


def pass_status_filter(siemplify, alert, status_filter):
    # status filter
    api_status_filter = []
    for status in convert_comma_separated_to_list(status_filter):
        api_status_filter.append(STATUSES_MAPPING.get(status.lower(), ""))
    if api_status_filter and alert.status not in api_status_filter:
        siemplify.LOGGER.info('Alert with status: {} did not pass filter. Acceptable statuses are: {}.'.
                              format(API_TO_UI_STATUSES_MAPPING.get(alert.status, "N/A"), status_filter))
        return False
    return True


if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test_run)