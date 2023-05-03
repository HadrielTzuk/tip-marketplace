import sys
from datetime import timedelta
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import output_handler, utc_now, convert_string_to_unix_time, convert_datetime_to_unix_time
from MicrosoftDefenderATPManager import MicrosoftDefenderATPManager
from MicrosoftDefenderATPTransformationLayer import MicrosoftDefenderATPTransformationLayer
from MicrosoftDefenderATPCommon import MicrosoftDefenderATPCommon
from EnvironmentCommon import GetEnvironmentCommonFactory
from TIPCommon import extract_connector_param, dict_to_flat, save_timestamp, get_last_success_time, \
    read_ids_by_timestamp, write_ids_with_timestamp, filter_old_alerts, is_overflowed


CONNECTOR_NAME = u"Microsoft Azure Sentinel Incidents Connector"
VENDOR = u"Microsoft Azure Sentinel"
PRODUCT = u"DummyProduct"
DEFAULT_VENDOR_NAME = u'Microsoft'
DEFAULT_PRODUCT_NAME = u'Microsoft Defender ATP'


@output_handler
def main(is_test_run):
    alerts = []
    all_alerts = []
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = CONNECTOR_NAME

    if is_test_run:
        siemplify.LOGGER.info(u"***** This is an \"IDE Play Button\" \"Run Connector once\" test run ******")

    siemplify.LOGGER.info(u"==================== Main - Param Init ====================")

    environment = extract_connector_param(
        siemplify,
        param_name=u'Environment Field Name',
        input_type=unicode,
        is_mandatory=False,
        print_value=True
    )

    environment_regex = extract_connector_param(
        siemplify,
        param_name=u'Environment Regex Pattern',
        input_type=unicode,
        is_mandatory=False,
        print_value=True
    )

    resource = extract_connector_param(
        siemplify,
        param_name=u'API Root',
        input_type=unicode,
        is_mandatory=True,
        print_value=True
    )

    integration_client_id = extract_connector_param(
        siemplify,
        param_name=u'Integration Client ID',
        input_type=unicode,
        is_mandatory=True,
        print_value=True
    )

    integration_client_secret = extract_connector_param(
        siemplify,
        param_name=u'Integration Client Secret',
        input_type=unicode,
        is_mandatory=True,
        print_value=False
    )

    siem_client_id = extract_connector_param(
        siemplify,
        param_name=u'SIEM Client ID',
        input_type=unicode,
        is_mandatory=True,
        print_value=True
    )

    siem_client_secret = extract_connector_param(
        siemplify,
        param_name=u'SIEM Client Secret',
        input_type=unicode,
        is_mandatory=True,
        print_value=False
    )

    tenant_id = extract_connector_param(
        siemplify,
        param_name=u'Azure Active Directory ID',
        input_type=unicode,
        is_mandatory=True,
        print_value=True
    )

    offset_hours = extract_connector_param(
        siemplify,
        param_name=u'Offset Time In Hours',
        input_type=int,
        is_mandatory=True,
        print_value=True
    )

    statuses = extract_connector_param(
        siemplify,
        param_name=u'Alert Statuses to Fetch',
        input_type=unicode,
        is_mandatory=True,
        print_value=True
    )

    severities = extract_connector_param(
        siemplify,
        param_name=u'Alert Severities to Fetch',
        input_type=unicode,
        is_mandatory=True,
        print_value=True
    )

    limit = extract_connector_param(
        siemplify,
        param_name=u'Max Alerts per Cycle',
        input_type=int,
        is_mandatory=True,
        print_value=True
    )

    statuses = MicrosoftDefenderATPManager.convert_comma_separated_to_list(statuses)
    severities = MicrosoftDefenderATPManager.convert_comma_separated_to_list(severities)

    siemplify.LOGGER.info(u"------------------- Main - Started -------------------")

    environment_common = GetEnvironmentCommonFactory.create_environment_manager(
        siemplify,
        environment,
        environment_regex
    )
    microsoft_defender_atp_common = MicrosoftDefenderATPCommon(siemplify.LOGGER)

    if is_test_run:
        siemplify.LOGGER.info(u"This is a test run. Ignoring stored timestamps")
        last_success_time_datetime = microsoft_defender_atp_common.validate_timestamp(
            utc_now() - timedelta(hours=offset_hours), offset_hours
        )
    else:
        last_success_time_datetime = get_last_success_time(siemplify, offset_with_metric={'hours': offset_hours})

    existing_ids = read_ids_by_timestamp(siemplify, offset_in_hours=offset_hours, convert_to_milliseconds=True)

    client = MicrosoftDefenderATPManager(
        client_id=integration_client_id,
        client_secret=integration_client_secret,
        tenant_id=tenant_id,
        resource=resource
    )

    siem_client = MicrosoftDefenderATPManager(
        client_id=siem_client_id,
        client_secret=siem_client_secret,
        tenant_id=tenant_id,
        resource='https://graph.windows.net'
    )

    if is_test_run:
        siemplify.LOGGER.info(u"This is a TEST run. Only 1 alert will be processed.")
        limit = 1

    fetched_alerts = client.get_alerts(
        alert_time_frame=offset_hours,
        statuses=statuses,
        severities=severities,
        limit=limit,
    )

    siemplify.LOGGER.info(u'{} alerts were fetched from timestamp {}'.format(
        len(fetched_alerts), last_success_time_datetime
    ))

    fetched_detections = siem_client.get_detections_siem(since_time_frame=offset_hours)
    siemplify.LOGGER.info(u'{} detection were fetched from timestamp {}'.format(
        len(fetched_detections), last_success_time_datetime
    ))

    filtered_alerts = filter_old_alerts(siemplify, fetched_alerts, existing_ids, 'id')

    siemplify.LOGGER.info(u"Found {} new alert in since {}."
                          .format(len(filtered_alerts), last_success_time_datetime.isoformat()))

    filtered_alerts = sorted(filtered_alerts, key=lambda alert: alert.alert_creation_time)

    for alert in filtered_alerts:
        try:
            siemplify.LOGGER.info(u"Processing alert {}".format(alert.id))
            events = list(filter(lambda event: event.alert_id == alert.id, fetched_detections))

            if not events:
                siemplify.LOGGER.info(
                    'Alert with "{}" with investigation state "{}" does not have any events. Skipping'.format(alert.id,
                                                                                                              alert.investigation_state))
                continue
            alert_info = create_alert_info(siemplify, environment_common, alert, events)

            if is_overflowed(siemplify, alert_info, is_test_run):
                siemplify.LOGGER.info(
                    u"{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping."
                        .format(
                        alert_name=alert_info.rule_generator,
                        alert_identifier=alert_info.ticket_id,
                        environment=alert_info.environment,
                        product=alert_info.device_product
                    )
                )
                continue

            alerts.append(alert_info)
            siemplify.LOGGER.info(u'Alert {} was created.'.format(alert.id))
            all_alerts.append(alert_info)
            existing_ids.update({alert.id: alert.alert_creation_time})

        except Exception as e:
            siemplify.LOGGER.error(u"Failed to process alert {}".format(alert.id), alert_id=alert.id)
            siemplify.LOGGER.exception(e)

            if is_test_run:
                raise

    if not is_test_run:
        if all_alerts:
            save_timestamp(siemplify, all_alerts, timestamp_key='start_time')

        write_ids_with_timestamp(siemplify, existing_ids)

    siemplify.LOGGER.info(u"Alerts Processed: {} of {}".format(len(alerts), len(all_alerts)))
    siemplify.LOGGER.info(u"Created total of {} alerts".format(len(alerts)))

    siemplify.LOGGER.info(u"------------------- Main - Finished -------------------")
    siemplify.return_package(alerts)


def create_alert_info(siemplify, environment_common, alert, events):
    siemplify.LOGGER.info(u"-------------- Started processing Alert {}".format(alert.id), alert_id=alert.id)

    alert_info = AlertInfo()

    alert_info.display_id = alert.id
    alert_info.ticket_id = alert.id
    alert_info.name = alert.title
    alert_info.description = alert.description
    alert_info.priority = MicrosoftDefenderATPTransformationLayer.calculate_priority(alert.severity)
    alert_info.start_time = convert_string_to_unix_time(alert.first_event_time)
    alert_info.end_time = convert_string_to_unix_time(alert.last_event_time)

    alert_info.device_vendor = DEFAULT_VENDOR_NAME
    alert_info.device_product = DEFAULT_PRODUCT_NAME
    alert_info.rule_generator = alert.detection_source

    alert_info.extensions = alert.to_extension()

    alert_info.events = [event.to_json() for event in events]

    alert_info.environment = environment_common.get_environment(alert)

    siemplify.LOGGER.info(u"-------------- Finished processing Alert {}".format(alert.id), alert_id=alert.id)
    return alert_info


if __name__ == "__main__":
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test_run)
