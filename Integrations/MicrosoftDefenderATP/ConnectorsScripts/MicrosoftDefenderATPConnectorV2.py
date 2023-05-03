import sys

from EnvironmentCommon import GetEnvironmentCommonFactory
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyUtils import output_handler, unix_now
from MicrosoftDefenderATPManager import MicrosoftDefenderATPManager
from TIPCommon import (
    extract_connector_param,
    read_ids,
    write_ids,
    is_overflowed,
    save_timestamp,
    get_last_success_time,
    is_approaching_timeout
)
from constants import AVAILABLE_STATUSES, AVAILABLE_SEVERITIES, STORED_IDS_LIMIT
from UtilsManager import pass_whitelist_filter, UNIX_FORMAT
from SiemplifyConnectorsDataModel import AlertInfo
from MicrosoftDefenderATPTransformationLayer import MicrosoftDefenderATPTransformationLayer


connector_starting_time = unix_now()
CONNECTOR_NAME = u"Microsoft Defender ATP Connector V2"


@output_handler
def main(is_test_run):
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = CONNECTOR_NAME
    processed_alerts = []

    if is_test_run:
        siemplify.LOGGER.info(u'***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******')

    siemplify.LOGGER.info(u'------------------- Main - Param Init -------------------')

    defender_atp_api_root = extract_connector_param(
        siemplify,
        param_name=u"Defender ATP API Root",
        is_mandatory=True,
        print_value=True
    )

    defender_api_root = extract_connector_param(
        siemplify,
        param_name=u"365 Defender API Root",
        is_mandatory=True,
        print_value=True
    )

    directory_id = extract_connector_param(
        siemplify,
        param_name=u"Azure Active Directory ID",
        is_mandatory=True,
        print_value=True
    )

    client_id = extract_connector_param(
        siemplify,
        param_name=u"Integration Client ID",
        is_mandatory=True,
        print_value=False
    )

    client_secret = extract_connector_param(
        siemplify,
        param_name=u"Integration Client Secret",
        is_mandatory=True,
        print_value=False
    )

    verify_ssl = extract_connector_param(
        siemplify,
        param_name=u"Verify SSL",
        is_mandatory=True,
        input_type=bool,
        print_value=False
    )

    environment = extract_connector_param(
        siemplify,
        param_name=u"Environment Field Name",
        print_value=True
    )

    environment_regex = extract_connector_param(
        siemplify,
        param_name=u"Environment Regex Pattern",
        print_value=True
    )

    offset_hours = extract_connector_param(
        siemplify,
        param_name=u"Offset Time In Hours",
        is_mandatory=True,
        input_type=int,
        print_value=True
    )

    limit = extract_connector_param(
        siemplify,
        param_name=u"Max Alerts per Cycle",
        is_mandatory=True,
        input_type=int,
        print_value=True
    )

    statuses = extract_connector_param(
        siemplify,
        param_name=u"Alert Statuses to Fetch",
        is_mandatory=True,
        print_value=True
    )

    severities = extract_connector_param(
        siemplify,
        param_name=u"Alert Severities to Fetch",
        is_mandatory=True,
        print_value=True
    )

    disable_overflow = extract_connector_param(
        siemplify,
        param_name=u"Disable Overflow",
        input_type=bool,
        print_value=True
    )

    whitelist_as_blacklist = extract_connector_param(
        siemplify,
        param_name=u"Use whitelist as a blacklist",
        input_type=bool,
        print_value=True
    )

    python_process_timeout = extract_connector_param(
        siemplify,
        param_name=u"PythonProcessTimeout",
        input_type=int,
        is_mandatory=True,
        print_value=True
    )

    device_product_field = extract_connector_param(
        siemplify,
        param_name="DeviceProductField",
        is_mandatory=True)

    statuses = MicrosoftDefenderATPManager.convert_comma_separated_to_list(statuses)
    severities = MicrosoftDefenderATPManager.convert_comma_separated_to_list(severities)
    common_environment = GetEnvironmentCommonFactory.create_environment_manager(
        siemplify, environment, environment_regex)

    try:
        siemplify.LOGGER.info(u'------------------- Main - Started -------------------')

        if not all(status in AVAILABLE_STATUSES for status in statuses):
            raise Exception(
                u"Invalid value provided for \"Alert Statuses to Fetch\" parameter. Possible values: {}"
                    .format(MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(AVAILABLE_STATUSES)))

        if not all(severity in AVAILABLE_SEVERITIES for severity in severities):
            raise Exception(
                u"Invalid value provided for \"Alert Severities to Fetch\" parameter. Possible values: {}"
                    .format(MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(AVAILABLE_SEVERITIES)))

        # Read already existing alerts ids
        siemplify.LOGGER.info(u'Reading already existing alerts ids...')
        existing_ids = read_ids(siemplify)
        siemplify.LOGGER.info(u"Successfully loaded {} existing ids".format(len(existing_ids)))

        client = MicrosoftDefenderATPManager(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=directory_id,
            resource=defender_atp_api_root,
            verify_ssl=verify_ssl,
            siemplify=siemplify
        )

        defender_api_client = MicrosoftDefenderATPManager(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=directory_id,
            resource=defender_atp_api_root,
            defender_api_resource=defender_api_root,
            verify_ssl=verify_ssl,
            siemplify=siemplify
        )

        fetched_alerts = []
        filtered_alerts = client.get_filtered_alerts(
            existing_ids=existing_ids,
            limit=limit,
            start_timestamp=get_last_success_time(siemplify=siemplify, offset_with_metric={u'hours': offset_hours},
                                                  time_format=UNIX_FORMAT),
            statuses=statuses,
            severities=severities)

        siemplify.LOGGER.info(u'Fetched {} alerts'.format(len(filtered_alerts)))

        if is_test_run:
            siemplify.LOGGER.info(u'This is a TEST run. Only 1 alert will be processed.')
            filtered_alerts = filtered_alerts[:1]

        for alert in filtered_alerts:
            try:
                if is_approaching_timeout(connector_starting_time, python_process_timeout):
                    siemplify.LOGGER.info(u'Timeout is approaching. Connector will gracefully exit')
                    break

                if len(processed_alerts) >= limit:
                    # Provide slicing for the alerts amount.
                    siemplify.LOGGER.info(
                        u'Reached max number of alerts cycle. No more alerts will be processed in this cycle.'
                    )
                    break

                siemplify.LOGGER.info(u'Started processing Alert {}'.format(alert.id))

                if not pass_filters(siemplify, whitelist_as_blacklist, alert, "detection_source"):
                    # Update existing alerts
                    existing_ids.append(alert.id)
                    fetched_alerts.append(alert)
                    continue

                alert.set_events(defender_api_client.get_alert_data(alert.id, alert.incident_id))

                # Update existing alerts
                existing_ids.append(alert.id)
                fetched_alerts.append(alert)

                alert_info = alert.get_alert_info(
                    AlertInfo(),
                    common_environment,
                    device_product_field=device_product_field,
                    severity=MicrosoftDefenderATPTransformationLayer.calculate_priority(alert.severity))

                if not disable_overflow:
                    if is_overflowed(siemplify, alert_info, is_test_run):
                        siemplify.LOGGER.info(
                            u"{}-{}-{}-{} found as overflow alert. Skipping...".format(
                                alert_info.rule_generator,
                                alert_info.ticket_id,
                                alert_info.environment,
                                alert_info.device_product
                            ))
                        # If is overflowed we should skip
                        continue

                processed_alerts.append(alert_info)
                siemplify.LOGGER.info(u"Alert {} was created.".format(alert.id))

            except Exception as e:
                siemplify.LOGGER.error(u"Failed to process alert {}".format(alert.id))
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise
            siemplify.LOGGER.info(u"Finished processing alert {}".format(alert.id))

        if not is_test_run:
            siemplify.LOGGER.info(u"Saving existing ids.")
            write_ids(siemplify, existing_ids, stored_ids_limit=STORED_IDS_LIMIT)
            save_timestamp(siemplify=siemplify, alerts=fetched_alerts, timestamp_key="alert_creation_time_timestamp")

        siemplify.LOGGER.info(u"Alerts processed: {} out of {}".format(len(processed_alerts), len(fetched_alerts)))

    except Exception as err:
        siemplify.LOGGER.error(u"Got exception on main handler. Error: {0}".format(err))
        siemplify.LOGGER.exception(err)

        if is_test_run:
            raise

    siemplify.LOGGER.info(u"Created total of {} alerts".format(len(processed_alerts)))
    siemplify.LOGGER.info(u"------------------- Main - Finished -------------------")
    siemplify.return_package(processed_alerts)


def pass_filters(siemplify, whitelist_as_a_blacklist, alert, model_key):
    # All alert filters should be checked here
    if not pass_whitelist_filter(siemplify, whitelist_as_a_blacklist, alert, model_key):
        return False

    return True


if __name__ == "__main__":
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test_run)
