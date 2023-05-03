import sys
from datetime import timedelta

from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import output_handler, utc_now, convert_string_to_unix_time, unix_now
from MicrosoftAzureSentinelManager import MicrosoftAzureSentinelManager
from MicrosoftAzureSentinelCommon import MicrosoftAzureSentinelCommon
from MicrosoftAzureSentinelParser import MicrosoftAzureSentinelParser
from EnvironmentCommon import GetEnvironmentCommonFactory
from TIPCommon import (
    extract_connector_param,
    dict_to_flat,
    read_ids_by_timestamp,
    write_ids_with_timestamp,
    is_overflowed,
    validate_timestamp
)

CONNECTOR_NAME = "Microsoft Azure Sentinel Incidents Connector"
VENDOR = "Microsoft Azure Sentinel"
PRODUCT = "DummyProduct"
DEFAULT_VENDOR_NAME = 'Vendor Name'
DEFAULT_PRODUCT_NAME = 'Product Name'
DEFAULT_PROVIDER_NAME = 'Provider Name'


@output_handler
def main(is_test_run):
    alerts = []
    all_alerts = []
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = CONNECTOR_NAME

    try:
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

        login_url = extract_connector_param(
            siemplify,
            param_name='OAUTH2 Login Endpoint Url',
            is_mandatory=True,
            print_value=True
        )

        client_id = extract_connector_param(
            siemplify,
            param_name='Client ID',
            is_mandatory=True,
            print_value=True
        )

        client_secret = extract_connector_param(
            siemplify,
            param_name='Client Secret',
            is_mandatory=True,
            print_value=False
        )

        tenant_id = extract_connector_param(
            siemplify,
            param_name='Azure Active Directory ID',
            is_mandatory=True,
            print_value=True
        )

        workspace_id = extract_connector_param(
            siemplify,
            param_name='Azure Sentinel Workspace Name',
            is_mandatory=True,
            print_value=True
        )

        subscription_id = extract_connector_param(
            siemplify,
            param_name='Azure Subscription ID',
            is_mandatory=True,
            print_value=True
        )

        resource = extract_connector_param(
            siemplify,
            param_name='Azure Resource Group',
            is_mandatory=True,
            print_value=True
        )

        verify_ssl = extract_connector_param(
            siemplify,
            param_name='Verify SSL',
            input_type=bool,
            print_value=True
        )

        offset_hours = extract_connector_param(
            siemplify,
            param_name='Offset Time In Hours',
            input_type=int,
            is_mandatory=True,
            print_value=True
        )

        statuses = extract_connector_param(
            siemplify,
            param_name='Incident Statuses to Fetch',
            is_mandatory=True,
            print_value=True
        )

        severities = extract_connector_param(
            siemplify,
            param_name='Incident Severities to Fetch',
            is_mandatory=True,
            print_value=True
        )

        limit = extract_connector_param(
            siemplify,
            param_name='Max Incidents per Cycle',
            input_type=int,
            is_mandatory=True,
            print_value=True
        )

        statuses = MicrosoftAzureSentinelManager.convert_comma_separated_to_list(statuses)
        severities = MicrosoftAzureSentinelManager.convert_comma_separated_to_list(severities)

        siemplify.LOGGER.info("------------------- Main - Started -------------------")

        environment_common = GetEnvironmentCommonFactory.create_environment_manager(
            siemplify, environment, environment_regex)
        sentinel_common = MicrosoftAzureSentinelCommon(siemplify.LOGGER)

        if is_test_run:
            siemplify.LOGGER.info("This is a test run. Ignoring stored timestamps")
            last_success_time_datetime = validate_timestamp(utc_now() - timedelta(hours=offset_hours), offset_hours)
        else:
            last_success_time_datetime = validate_timestamp(
                siemplify.fetch_timestamp(datetime_format=True), offset_hours)

        # Read already existing alerts ids
        existing_ids = read_ids_by_timestamp(
            siemplify=siemplify, offset_in_hours=offset_hours, convert_to_milliseconds=True)

        sentinel_manager = MicrosoftAzureSentinelManager(
            api_root=api_root,
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            resource=resource,
            subscription_id=subscription_id,
            login_url=login_url,
            verify_ssl=verify_ssl,
            logger=siemplify.LOGGER
        )

        fetched_alerts = sentinel_manager.get_incidents(
            creation_time=last_success_time_datetime,
            statuses=statuses,
            severities=severities,
            limit=limit,
            extend_alerts=True
        )

        filtered_alerts = sentinel_common.filter_old_ids(fetched_alerts, existing_ids)

        if fetched_alerts and not filtered_alerts:
            # If there are fetched_alerts, but filtered_alerts is empty, then it means that we probably are stuck
            # in a loop because several incidents have the same timestamp, and using the limit causes the API
            # to return the same incidents over and over again (as start time is not changing in the query).
            # We will try to bring new incidents without the limit (in the query) and limiting manually in connector
            # code. So the connector will try to bring ALL incidents since last_success_time_datetime, filter the
            # already seen ones and advance. Notice that this type of querying is costly performance-wise as it will
            # bring every incident since the timestamp. We want to avoid those as much as we can, by setting large
            # enough "Max Incidents per Cycle", and by having a not so large "Offset Time In Hours".
            fetched_alerts = sentinel_manager.get_incidents(
                creation_time=last_success_time_datetime,
                statuses=statuses,
                severities=severities,
                extend_alerts=True
            )
            filtered_alerts = sentinel_common.filter_old_ids(fetched_alerts, existing_ids)

        siemplify.LOGGER.info("Found {} new alert in since {}."
                              .format(len(filtered_alerts), last_success_time_datetime.isoformat()))

        if is_test_run:
            siemplify.LOGGER.info("This is a TEST run. Only 1 alert will be processed.")
            filtered_alerts = filtered_alerts[:1]

        filtered_alerts = sorted(filtered_alerts, key=lambda alert: alert.properties.created_time_utc)[:limit]

        for alert in filtered_alerts:
            try:
                siemplify.LOGGER.info("Processing alert {} - {}".format(alert.name, alert.properties.created_time_utc))
                alert_info = create_alert_info(siemplify, environment_common, alert)

                overflowed = is_overflowed(siemplify, alert_info, is_test_run)

                if overflowed:
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
                    siemplify.LOGGER.info('Alert {} was created.'.format(alert.name))

                all_alerts.append(alert_info)
                existing_ids.update({alert.name: unix_now()})

            except Exception as e:
                siemplify.LOGGER.error("Failed to process alert {}".format(alert.name), alert_id=alert.name)
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

        if not is_test_run and all_alerts:
            all_alerts = sorted(all_alerts, key=lambda _alert: _alert.start_time)
            siemplify.save_timestamp(new_timestamp=all_alerts[-1].start_time)
            write_ids_with_timestamp(siemplify=siemplify, ids=existing_ids)

        siemplify.LOGGER.info("Alerts Processed: {} of {}".format(len(alerts), len(all_alerts)))
        siemplify.LOGGER.info("Created total of {} alerts".format(len(alerts)))

        siemplify.LOGGER.info("------------------- Main - Finished -------------------")
        siemplify.return_package(alerts)

    except Exception as e:
        error_message = 'Got exception on main handler. Error: {0}'.format(e)

        if is_test_run:
            raise

        siemplify.LOGGER.error(error_message)
        siemplify.LOGGER.exception(e)


def create_alert_info(siemplify, environment_common, alert):
    siemplify.LOGGER.info("-------------- Started processing Alert {}".format(alert.name), alert_id=alert.name)

    alert_info = AlertInfo()

    alert_info.display_id = alert.name
    alert_info.ticket_id = alert.name
    alert_info.name = alert.properties.title
    alert_info.rule_generator = alert.properties.title
    alert_info.description = alert.properties.description
    alert_info.priority = MicrosoftAzureSentinelParser.calculate_priority(alert.properties.severity)
    alert_info.start_time = convert_string_to_unix_time(alert.properties.first_alert_time_generated)
    alert_info.end_time = convert_string_to_unix_time(alert.properties.last_alert_time_generated)

    alert_info.device_vendor = alert.properties.alerts[0].get('VendorName') \
        if alert.properties.alerts else DEFAULT_VENDOR_NAME
    alert_info.device_product = alert.properties.alerts[0].get('ProductName') \
        if alert.properties.alerts else DEFAULT_PRODUCT_NAME

    alert_info.extensions = dict_to_flat({
        'status': alert.properties.status,
        'labels': alert.properties.labels,
        'endTimeUtc': alert.properties.end_time_utc,
        'startTimeUtc': alert.properties.start_time_utc,
        'owner': alert.properties.owner.to_json(),
        'lastUpdatedTimeUtc': alert.properties.last_updated_time_utc,
        'createdTimeUtc': alert.properties.created_time_utc,
        'relatedAlertIds': alert.properties.related_alert_ids,
        'caseNumber': alert.properties.case_number,
        'totalComments': alert.properties.total_comments,
        'metrics': alert.properties.metrics,
    })

    events = []
    for al in alert.properties.alerts:
        if al.get('ProviderName') == 'ASI Scheduled Alerts':
            # Need to "unwrap" the alert with the events that were fetched for it by its query
            alert_events = al.get('Events', [])

            if alert_events:
                events.extend(alert_events)

            else:
                # No events in the ASI alert - use the alert itself as the event
                events.append(al)
        else:
            # Use the alert itself as the event
            events.append(al)

    alert_info.events = list(map(dict_to_flat, events))
    alert_info.environment = environment_common.get_environment(dict_to_flat(alert.raw_data))

    siemplify.LOGGER.info("-------------- Finished processing Alert {}".format(alert.name), alert_id=alert.name)
    return alert_info


if __name__ == "__main__":
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test_run)
