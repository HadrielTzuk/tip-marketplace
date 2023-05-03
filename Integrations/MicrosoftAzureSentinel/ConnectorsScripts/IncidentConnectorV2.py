import sys
import json
from datetime import timedelta

from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import output_handler, utc_now, convert_string_to_unix_time, unix_now, convert_string_to_datetime
from MicrosoftAzureSentinelManager import MicrosoftAzureSentinelManager
from MicrosoftAzureSentinelCommon import (
    MicrosoftAzureSentinelCommon,
    is_date,
    validate_backlog,
    validate_incidents_numbers,
    validate_alerts_next_page,
    read_backlog_ids,
    read_next_page_alerts,
    read_incidents_numbers,
    write_next_page_alerts,
    write_incidents_numbers,
    write_backlog_ids
)
from MicrosoftAzureSentinelParser import MicrosoftAzureSentinelParser
from EnvironmentCommon import GetEnvironmentCommonFactory
from TIPCommon import (
    extract_connector_param,
    dict_to_flat,
    is_overflowed,
    siemplify_fetch_timestamp,
    siemplify_save_timestamp,
    validate_timestamp,
    read_ids_by_timestamp,
    write_ids_with_timestamp
)
from exceptions import TimeoutIsApproachingError, MicrosoftAzureSentinelManagerError
from utils import handle_special_characters, get_value_from_template, find_fallback_value

from constants import NRT_ALERT_TYPE_STRING, NRT_ALERT_EVENT_KIND, SCHEDULED_ALERT_EVENT_KIND

CONNECTOR_NAME = "Microsoft Azure Sentinel Incidents Connector v2"
DEFAULT_VENDOR_NAME = 'MicrosoftAzureSentinel'
DEFAULT_PRODUCT_NAME = 'Product Name'
DEFAULT_PROVIDER_NAME = 'Provider Name'
WHITELIST_FILTER = 'whitelist'
BLACKLIST_FILTER = 'blacklist'
MAX_INCIDENTS_PER_CYCLE = 10
MAX_BACKLOG_INCIDENTS_PER_CYCLE = 10
SCHEDULED_ALERTS_EVENTS_DEFAULT_LIMIT = 100
MAX_INCIDENTS_NUMBERS_TO_SAVE = 1000
connector_starting_time = unix_now()
DEFAULT_INCIDENTS_ALERTS_LIMIT_TO_INGEST = 10


@output_handler
def main(is_test_run):
    all_alerts = []
    processed_alerts = []
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

        subscription_id = extract_connector_param(
            siemplify,
            param_name='Azure Subscription ID',
            is_mandatory=True,
            print_value=True
        )

        tenant_id = extract_connector_param(
            siemplify,
            param_name='Azure Active Directory ID',
            is_mandatory=True,
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

        resource = extract_connector_param(
            siemplify,
            param_name='Azure Resource Group',
            is_mandatory=True,
            print_value=True
        )

        workspace_id = extract_connector_param(
            siemplify,
            param_name='Azure Sentinel Workspace Name',
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

        verify_ssl = extract_connector_param(
            siemplify,
            param_name='Verify SSL',
            input_type=bool,
            print_value=True
        )

        limit = extract_connector_param(
            siemplify,
            param_name='Max New Incidents Per Cycle',
            input_type=int,
            is_mandatory=True,
            print_value=True,
            default_value=MAX_INCIDENTS_PER_CYCLE
        )
        limit = limit and max(0, limit)

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

        use_same_approach = extract_connector_param(
            siemplify,
            param_name='Use the same approach with event creation for all alert types?',
            input_type=bool,
            print_value=True
        )

        python_process_timeout = extract_connector_param(
            siemplify, param_name="PythonProcessTimeout",
            input_type=int,
            is_mandatory=True,
            print_value=True
        )

        alerts_padding_period = extract_connector_param(
            siemplify,
            param_name='Alerts Padding Period',
            input_type=int,
            is_mandatory=True,
            print_value=True
        )

        incidents_padding_period = extract_connector_param(
            siemplify,
            param_name='Incidents Padding Period (minutes)',
            input_type=int,
            print_value=True
        )

        whitelist_as_a_blacklist = extract_connector_param(
            siemplify,
            param_name='Use whitelist as a blacklist',
            is_mandatory=True,
            input_type=bool,
            print_value=True
        )

        event_field_fallback = extract_connector_param(
            siemplify,
            param_name='EventFieldFallback',
            is_mandatory=True,
            print_value=True
        )

        product_field_fallback = extract_connector_param(
            siemplify,
            param_name='ProductFieldFallback',
            is_mandatory=True,
            print_value=True
        )

        vendor_field_fallback = extract_connector_param(
            siemplify,
            param_name='VendorFieldFallback',
            is_mandatory=True,
            print_value=True
        )

        start_time_fallback = extract_connector_param(
            siemplify,
            param_name='StartTimeFallback',
            is_mandatory=True,
            print_value=True
        )

        end_time_fallback = extract_connector_param(
            siemplify,
            param_name='EndTimeFallback',
            is_mandatory=True,
            print_value=True
        )

        fallback_logic_debug = extract_connector_param(
            siemplify,
            param_name='Enable Fallback Logic Debug?',
            input_type=bool,
            print_value=True
        )

        max_backlog_limit_per_cycle = extract_connector_param(
            siemplify,
            param_name='Max Backlog Incidents per cycle',
            input_type=int,
            print_value=True,
            default_value=MAX_BACKLOG_INCIDENTS_PER_CYCLE
        )

        scheduled_alerts_events_limit = extract_connector_param(
            siemplify,
            param_name='Scheduled Alerts Events Limit to Ingest',
            input_type=int,
            print_value=True,
            default_value=SCHEDULED_ALERTS_EVENTS_DEFAULT_LIMIT
        )

        alerts_for_no_entities = extract_connector_param(
            siemplify,
            param_name='Create Siemplify Alerts for Sentinel incidents that do not have entities?',
            input_type=bool,
            print_value=True
        )

        incidents_alerts_limit_to_ingest = extract_connector_param(
            siemplify,
            param_name="Incident's Alerts Limit to Ingest",
            input_type=int,
            print_value=True,
            default_value=DEFAULT_INCIDENTS_ALERTS_LIMIT_TO_INGEST
        )

        alert_name_template = extract_connector_param(
            siemplify,
            param_name="Alert Name Template",
            input_type=str,
            print_value=True,
            is_mandatory=False
        )
        rule_generator_template = extract_connector_param(
            siemplify,
            param_name="Rule Generator Template",
            input_type=str,
            print_value=True,
            is_mandatory=False
        )

        whitelist_filter_type = BLACKLIST_FILTER if whitelist_as_a_blacklist else WHITELIST_FILTER

        whitelist = [handle_special_characters(item) for item in siemplify.whitelist]

        event_field_fallback = MicrosoftAzureSentinelManager.convert_comma_separated_to_list(event_field_fallback)
        product_field_fallback = MicrosoftAzureSentinelManager.convert_comma_separated_to_list(product_field_fallback)
        vendor_field_fallback = MicrosoftAzureSentinelManager.convert_comma_separated_to_list(vendor_field_fallback)
        start_time_fallback = MicrosoftAzureSentinelManager.convert_comma_separated_to_list(start_time_fallback)
        end_time_fallback = MicrosoftAzureSentinelManager.convert_comma_separated_to_list(end_time_fallback)
        statuses = MicrosoftAzureSentinelManager.convert_comma_separated_to_list(statuses)
        severities = MicrosoftAzureSentinelManager.convert_comma_separated_to_list(severities)

        siemplify.LOGGER.info("------------------- Main - Started -------------------")

        if incidents_padding_period is not None and incidents_padding_period < 0:
            raise Exception(f"\"Incidents Padding Period (minutes)\" must be non-negative")

        environment_common = GetEnvironmentCommonFactory.create_environment_manager(
            siemplify, environment, environment_regex)
        sentinel_common = MicrosoftAzureSentinelCommon(siemplify.LOGGER)

        validate_backlog(siemplify)
        validate_alerts_next_page(siemplify)
        validate_incidents_numbers(siemplify)

        # reading backlog_ids file
        siemplify.LOGGER.info("Reading backlog IDs")
        backlog_ids = read_backlog_ids(siemplify)
        siemplify.LOGGER.info(f"Number of items in backlog IDs: {len(backlog_ids.items())}")

        if is_test_run:
            siemplify.LOGGER.info("This is a test run. Ignoring stored timestamps")
            last_success_time_datetime = validate_timestamp(utc_now() - timedelta(hours=offset_hours), offset_hours)
        else:
            last_success_time_datetime = validate_timestamp(
                siemplify_fetch_timestamp(siemplify, datetime_format=True), offset_hours)

        if incidents_padding_period is not None \
                and last_success_time_datetime > utc_now() - timedelta(minutes=incidents_padding_period):
            last_success_time_datetime = utc_now() - timedelta(minutes=incidents_padding_period)
            siemplify.LOGGER.info(f"Last success time is greater than incidents padding period. Unix: "
                                  f"{last_success_time_datetime.timestamp()} will be used as last success time")

        # Read already existing alerts ids
        siemplify.LOGGER.info("Reading IDs")
        existing_ids = read_ids_by_timestamp(siemplify, convert_to_milliseconds=True)
        siemplify.LOGGER.info(f"Number of items IDs: {len(existing_ids.items())}")

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

        siemplify.LOGGER.info("Reading page link")
        next_page_link = read_next_page_alerts(siemplify)

        fetched_alerts, next_page_link = sentinel_manager.get_incidents_with_new_endpoint(
            creation_time=last_success_time_datetime,
            statuses=statuses,
            severities=severities,
            limit=limit,
            asc=True,
            use_same_approach=use_same_approach,
            existing_ids=existing_ids,
            next_page_link=next_page_link,
            connector_starting_time=connector_starting_time,
            python_process_timeout=python_process_timeout,
            scheduled_alerts_events_limit=scheduled_alerts_events_limit,
            incidents_alerts_limit_to_ingest=incidents_alerts_limit_to_ingest,
            backlog_ids=backlog_ids,
        )
        siemplify.LOGGER.info(f"Number of fetched alerts: {len(fetched_alerts)}")

        filtered_alerts = sentinel_common.filter_old_ids(fetched_alerts, existing_ids)
        siemplify.LOGGER.info(f"Number of filtered alerts by ID: {len(filtered_alerts)}")

        if filtered_alerts:
            if filtered_alerts[-1].properties.created_time_unix > last_success_time_datetime.timestamp():
                siemplify.LOGGER.info("Writing next page")
                write_next_page_alerts(siemplify, '')

        elif next_page_link:
            siemplify.LOGGER.info(f"Writing next page")
            write_next_page_alerts(siemplify, json.dumps(next_page_link))

        else:
            siemplify.LOGGER.info("Writing next page")
            write_next_page_alerts(siemplify, '')

        siemplify.LOGGER.info("Found {} new alerts since {}."
                              .format(len(filtered_alerts), last_success_time_datetime.isoformat()))

        filtered_alerts = sorted(filtered_alerts, key=lambda _alert: _alert.properties.created_time_utc)
        siemplify.LOGGER.info(f"Number of sorted alerts: {len(filtered_alerts)}")

        siemplify.LOGGER.info("Starting processing backlog alerts.")
        fetched_backlog_alerts = []
        while True:
            if sentinel_common.is_approaching_timeout(connector_starting_time, python_process_timeout) or \
                    len(fetched_backlog_alerts) >= max_backlog_limit_per_cycle:
                break
            current_backlog_incidents = get_backlog_incidents(
                siemplify=siemplify,
                sentinel_manager=sentinel_manager,
                backlog_ids=backlog_ids,
                filtered_alerts=filtered_alerts,
                python_process_timeout=python_process_timeout,
                incidents_alerts_limit_to_ingest=incidents_alerts_limit_to_ingest,
                limit=min(max_backlog_limit_per_cycle - len(fetched_backlog_alerts), 10),
                use_same_approach=use_same_approach,
                scheduled_alerts_events_limit=scheduled_alerts_events_limit
            )
            fetched_backlog_alerts.extend(current_backlog_incidents)
            filtered_alerts.extend(current_backlog_incidents)
            if not current_backlog_incidents:
                break

        siemplify.LOGGER.info(f'Fetched {len(fetched_backlog_alerts)} backlog alerts.')
        siemplify.LOGGER.info(f'Total alerts to process {len(filtered_alerts)}')

        alerts_to_backlog = []
        alerts_to_create = []

        siemplify.LOGGER.info("Reading incident numbers")
        existing_incidents_numbers = read_incidents_numbers(siemplify)
        siemplify.LOGGER.info(f"Number of incident numbers: {len(existing_incidents_numbers)}")

        for alert in filtered_alerts:
            if is_test_run and len(all_alerts) >= 1:
                siemplify.LOGGER.info("This is a TEST run. Only 1 alert will be processed.")
                break

            try:
                siemplify.LOGGER.info("-------------- Started processing Alert {}".format(alert.name),
                                      alert_id=alert.name)

                if sentinel_common.is_approaching_timeout(connector_starting_time, python_process_timeout):
                    siemplify.LOGGER.info('Timeout is approaching. Connector will gracefully exit')
                    break

                backlog_timer = alerts_padding_period * 60 * 1000

                # checking if fetched incidents contain entities
                if use_same_approach or all(not isinstance(item, dict) for item in alert.properties.alerts):
                    if all(item.entities or (alerts_for_no_entities and item.entities is not None)
                           for item in alert.properties.alerts):
                        if str(alert.properties.incident_number) in backlog_ids:
                            if unix_now() < backlog_ids.get(
                                    str(alert.properties.incident_number), 0) + backlog_timer:
                                siemplify.LOGGER.info(
                                    f'Backlog alert {alert.properties.incident_number} will be processed')
                                alerts_to_create.append(alert)
                            elif alerts_for_no_entities:
                                siemplify.LOGGER.info("Expired backlog alert {} ({}) will be processed."
                                                      .format(alert.name, alert.properties.incident_number))
                                alerts_to_create.append(alert)
                            else:
                                siemplify.LOGGER.info(f'Backlog alert {alert.properties.incident_number} expired')

                        else:
                            siemplify.LOGGER.info(f'Regular alert {alert.properties.incident_number} will be processed')
                            alerts_to_create.append(alert)
                    else:
                        if str(alert.properties.incident_number) not in backlog_ids:
                            if not pass_whitelist_filter(siemplify, alert, whitelist, whitelist_filter_type):
                                siemplify.LOGGER.info('Alert {} did not pass filters skipping....'.format(alert.name))
                            else:
                                siemplify.LOGGER.info("Sending alert {} ({}) to backlog"
                                                      .format(alert.name, alert.properties.incident_number))
                                alerts_to_backlog.append(alert)
                        elif alerts_for_no_entities and unix_now() >= backlog_ids.get(
                                str(alert.properties.incident_number), 0) + backlog_timer:
                            siemplify.LOGGER.info("Expired backlog alert {} ({}) with no entities will be "
                                                  "processed.".format(alert.name, alert.properties.incident_number))
                            alerts_to_create.append(alert)
                        else:
                            siemplify.LOGGER.info("Alert {} ({}) is already in backlog".format(
                                alert.name, alert.properties.incident_number))

                        siemplify.LOGGER.info('Finished processing Alert {}'.format(alert.name),
                                              alert_id=alert.name)
                else:
                    if alert.properties.alerts and all(scheduled_alert.get("Events") for scheduled_alert in alert.properties.alerts):
                        if str(alert.properties.incident_number) in backlog_ids:
                            siemplify.LOGGER.info(
                                f"Backlog alert {alert.properties.incident_number} will be processed"
                            )
                            alerts_to_create.append(alert)
                        else:
                            siemplify.LOGGER.info(
                                f"Regular alert {alert.properties.incident_number} will be processed"
                            )
                            alerts_to_create.append(alert)
                    else:
                        if str(alert.properties.incident_number) not in backlog_ids:
                            if not pass_whitelist_filter(siemplify, alert, whitelist, whitelist_filter_type):
                                siemplify.LOGGER.info(
                                    f"Alert {alert.name} did not pass filters skipping...."
                                )
                            else:
                                siemplify.LOGGER.info(
                                    f"Sending alert {alert.name} ({alert.properties.incident_number}) to backlog"
                                )
                                alerts_to_backlog.append(alert)
                        elif unix_now() < backlog_ids.get(str(alert.properties.incident_number), 0) + backlog_timer:
                            siemplify.LOGGER.info(
                                f"Alert {alert.name} ({alert.properties.incident_number}) is already in backlog"
                            )
                        else:
                            siemplify.LOGGER.info(
                                f"Expired backlog alert {alert.name} ({alert.properties.incident_number})"
                                f" with no events will be processed."
                            )
                            alerts_to_create.append(alert)

                        siemplify.LOGGER.info('Finished processing Alert {}'.format(alert.name),
                                              alert_id=alert.name)

                ingested_alert_ids = [str(alert_to_create.properties.incident_number) for alert_to_create in
                                      alerts_to_create]

                siemplify.LOGGER.info("Updating processed alerts")
                processed_alerts.append(alert)
                siemplify.LOGGER.info(f"Number of processed alerts: {len(processed_alerts)}")

                if str(alert.properties.incident_number) not in ingested_alert_ids:
                    continue

                if not pass_whitelist_filter(siemplify, alert, whitelist, whitelist_filter_type):
                    siemplify.LOGGER.info('Alert {} did not pass filters skipping....'.format(alert.name))
                    continue

                alert_info = create_alert_info(siemplify=siemplify,
                                               environment_common=environment_common,
                                               alert=alert,
                                               vendor_field_fallback=vendor_field_fallback,
                                               product_field_fallback=product_field_fallback,
                                               event_field_fallback=event_field_fallback,
                                               start_time_fallback=start_time_fallback,
                                               end_time_fallback=end_time_fallback,
                                               fallback_logic_debug=fallback_logic_debug,
                                               use_same_approach=use_same_approach,
                                               alert_name_template=alert_name_template,
                                               rule_generator_template=rule_generator_template)

                if is_overflowed(siemplify, alert_info, is_test_run):
                    siemplify.LOGGER.info(
                        '{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping.'
                            .format(alert_name=alert_info.rule_generator,
                                    alert_identifier=alert_info.ticket_id,
                                    environment=alert_info.environment,
                                    product=alert_info.device_product))
                    # If is overflowed we should skip
                    continue

                all_alerts.append(alert_info)
                siemplify.LOGGER.info('Alert {} was created.'.format(alert.name))
            except Exception as e:
                siemplify.LOGGER.error("Failed to process alert {}".format(alert.name), alert_id=alert.name)
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            siemplify.LOGGER.info('Finished processing Alert {}'.format(alert.name), alert_id=alert.name)

        if not is_test_run:
            # Processing backlog
            new_backlog = update_backlog(siemplify, alerts_to_create, backlog_ids,
                                         alerts_to_backlog, alerts_padding_period)
            if sorted(backlog_ids) != sorted(new_backlog):
                siemplify.LOGGER.info("Writing backlog in main")
                write_backlog_ids(siemplify, new_backlog)
                siemplify.LOGGER.info(f"Number of IDs in written backlog: {len(new_backlog)}")

            # Processing timestamp
            processed_alerts_with_timestamp = [
                item for item in processed_alerts
                if item.properties.created_time_utc
                and str(item.properties.incident_number) not in new_backlog
            ]

            if processed_alerts_with_timestamp:
                alerts_with_timestamp = sorted(processed_alerts_with_timestamp, key=lambda _alert: _alert.properties.
                                               created_time_utc)
                new_timestamp = alerts_with_timestamp[-1].properties.created_time_utc
                siemplify_save_timestamp(siemplify, new_timestamp=(convert_string_to_unix_time(new_timestamp)))
                siemplify.LOGGER.info(
                    'New timestamp {} has been saved'
                    .format(convert_string_to_datetime(new_timestamp).isoformat())
                )

            # Processing id files
            new_existing_ids = {alert.name: unix_now() for alert in processed_alerts}
            if new_existing_ids:
                existing_ids.update(new_existing_ids)
                siemplify.LOGGER.info("Writing IDs")
                write_ids_with_timestamp(siemplify, existing_ids)
                siemplify.LOGGER.info(f"Number of IDs to write: {len(existing_ids)}")

            new_existing_incidents_numbers = [alert.extensions["incidentNumber"] for alert in all_alerts]
            if new_existing_incidents_numbers:
                existing_incidents_numbers.extend(new_existing_incidents_numbers)
                existing_incidents_numbers = existing_incidents_numbers[-MAX_INCIDENTS_NUMBERS_TO_SAVE:]
                siemplify.LOGGER.info("Writing incident-numbers")
                write_incidents_numbers(siemplify, existing_incidents_numbers)
                siemplify.LOGGER.info(f"Number of incidents-numbers to write: {len(existing_incidents_numbers)}")

    except TimeoutIsApproachingError:
        siemplify.LOGGER.info('Timeout is approaching. Connector will gracefully exit')

    except MicrosoftAzureSentinelManagerError as error:
        log_message = f'Got exception on main handler. Error: {error}'
        if error.error_context:
            log_message += f", error context: {error.error_context}"

        siemplify.LOGGER.error(log_message)
        siemplify.LOGGER.exception(error)

        if is_test_run:
            raise

    except Exception as e:
        siemplify.LOGGER.error(f'Got exception on main handler. Error: {e}')
        siemplify.LOGGER.exception(e)

        if is_test_run:
            raise

    siemplify.LOGGER.info("Created total of {} cases".format(len(all_alerts)))
    siemplify.LOGGER.info("------------------- Main - Finished -------------------")
    siemplify.return_package(all_alerts)


def update_backlog(siemplify, alerts_to_create, backlog_ids, alerts_to_backlog,
                   alerts_padding_period):
    new_backlog = {}
    ingested_alert_ids = [
        str(alert_to_create.properties.incident_number)
        for alert_to_create in alerts_to_create
    ]

    for alert_num, time in backlog_ids.items():
        if alert_num not in ingested_alert_ids and unix_now() < time + alerts_padding_period * 60 * 1000:
            siemplify.LOGGER.info(
                f'Keeping {alert_num} in backlog...')
            new_backlog[alert_num] = time

    for backlog_alert in alerts_to_backlog:
        incident_number = str(backlog_alert.properties.incident_number)
        if incident_number not in new_backlog:
            new_backlog[incident_number] = unix_now()
    return new_backlog


def get_backlog_incidents(siemplify, sentinel_manager, backlog_ids, filtered_alerts,
                          python_process_timeout, incidents_alerts_limit_to_ingest,
                          limit=MAX_BACKLOG_INCIDENTS_PER_CYCLE, use_same_approach=False,
                          scheduled_alerts_events_limit=None):
    incidents = []

    counter = 0
    for inc_number in backlog_ids:
        if counter >= limit:
            siemplify.LOGGER.info("Limit of backlog id's to process per cycle is reached, exiting ...")
            break

        if inc_number not in [str(incident.properties.incident_number) for incident in filtered_alerts]:
            siemplify.LOGGER.info(f"Fetching data for backlog incident {inc_number}")
            incidents.append(sentinel_manager.get_incident_by_number(
                incident_number=inc_number,
                connector_starting_time=connector_starting_time,
                python_process_timeout=python_process_timeout,
                incidents_alerts_limit_to_ingest=incidents_alerts_limit_to_ingest,
                use_same_approach=use_same_approach,
                scheduled_alerts_events_limit=scheduled_alerts_events_limit,
                backlog_ids=backlog_ids))
            counter += 1

    return incidents


def create_alert_info(siemplify, environment_common, alert, vendor_field_fallback, product_field_fallback,
                      event_field_fallback, start_time_fallback, end_time_fallback, fallback_logic_debug,
                      use_same_approach=False, alert_name_template="", rule_generator_template=""):
    flat_incident = alert.raw_to_flat_data()
    alert_info = AlertInfo()

    alert_info.display_id = alert.name
    alert_info.ticket_id = alert.name
    alert_info.name = get_value_from_template(
        template=alert_name_template,
        data=flat_incident,
        default_value=alert.properties.title,
    )
    alert_info.rule_generator = get_value_from_template(
        template=rule_generator_template,
        data=flat_incident,
        default_value=alert.properties.title,
    )
    alert_info.description = alert.properties.description
    alert_info.priority = MicrosoftAzureSentinelParser.calculate_priority(alert.properties.severity)

    start_time = alert.properties.created_time_utc
    end_time = alert.properties.created_time_utc

    for item in start_time_fallback:
        if flat_incident.get(item):
            start_time = flat_incident[item]
            if fallback_logic_debug:
                flat_incident["StartTimeFallback"] = item
            break

    for item in end_time_fallback:
        if flat_incident.get(item):
            end_time = flat_incident[item]
            if fallback_logic_debug:
                flat_incident["EndTimeFallback"] = item
            break

    if start_time:
        alert_info.start_time = convert_string_to_unix_time(start_time)
        if fallback_logic_debug and not flat_incident.get("StartTimeFallback"):
            flat_incident["StartTimeFallback"] = "CreatedTimeUTC"
    else:
        alert_info.start_time = unix_now()
        siemplify.LOGGER.info("Siemplify Alert's start time is set to current time, as no values were found with the "
                              "provided fallback fields.")
        if fallback_logic_debug:
            flat_incident["StartTimeFallback"] = "Current time"

    if end_time:
        alert_info.end_time = convert_string_to_unix_time(end_time)
        if fallback_logic_debug and not flat_incident.get("EndTimeFallback"):
            flat_incident["EndTimeFallback"] = "CreatedTimeUTC"
    else:
        alert_info.end_time = unix_now()
        siemplify.LOGGER.info("Siemplify Alert's end time is set to current time, as no values were found with the "
                              "provided fallback fields.")
        if fallback_logic_debug:
            flat_incident["EndTimeFallback"] = "Current time"

    if alert.properties.alerts:
        source_alert = alert.properties.alerts[0]
        if isinstance(source_alert, dict):
            device_vendor = source_alert.get("VendorName")
            flat_event = (
                dict_to_flat(source_alert.get("Events")[0])
                if source_alert.get("Events")
                else {}
            )
            device_product, _ = find_fallback_value(
                source_dicts = [flat_event, dict_to_flat(source_alert), flat_incident],
                fallbacks_list= product_field_fallback
            )
        else:
            device_product, _ = find_fallback_value(
                source_dicts=[dict_to_flat(source_alert.to_event()), flat_incident],
                fallbacks_list=product_field_fallback
            )
            device_vendor = source_alert.properties.vendor_name
    else:
        product_value = None
        vendor_value = None

        for item in product_field_fallback:
            if flat_incident.get(item):
                product_value = flat_incident[item]
                if fallback_logic_debug:
                    flat_incident["ProductFieldFallback"] = item
                break

        for item in vendor_field_fallback:
            if flat_incident.get(item):
                vendor_value = flat_incident[item]
                if fallback_logic_debug:
                    flat_incident["VendorFieldFallback"] = item
                break

        device_vendor = vendor_value if vendor_value else DEFAULT_VENDOR_NAME
        device_product = product_value if product_value else DEFAULT_PRODUCT_NAME

    alert_info.device_vendor = device_vendor
    alert_info.device_product = device_product

    alert_info.extensions = dict_to_flat({
        'status': alert.properties.status,
        'labels': [str(label) for label in alert.properties.labels],
        'endTimeUtc': alert.properties.end_time_utc,
        'startTimeUtc': alert.properties.start_time_utc,
        'owner': alert.properties.owner.assigned_to if alert.properties.owner else None,
        'lastModifiedTimeUtc': alert.properties.last_modified_time_utc,
        'createdTimeUtc': alert.properties.created_time_utc,
        'incidentNumber': alert.properties.incident_number,
        'additionalData': alert.properties.additional_data
    })
    events = [] if alert.properties.alerts else [dict_to_flat(alert.to_event())]

    for incident_alert in alert.properties.alerts:
        if isinstance(incident_alert, dict) and not use_same_approach:
            # Need to "unwrap" the alert with the events that were fetched for it by its query
            alert_events = list(map(dict_to_flat, incident_alert.get('Events', [])))
            incident_alert_flat = dict_to_flat(incident_alert)

            if alert_events:
                for event in alert_events:
                    product_value, product_fallback_field = find_fallback_value(
                        source_dicts=[event, incident_alert_flat, flat_incident],
                        fallbacks_list=product_field_fallback
                    )
                    if product_fallback_field is not None:
                        event["product_type"] = product_value
                        if fallback_logic_debug:
                            event["ProductFieldFallback"] = product_fallback_field

                    event["kind"] = NRT_ALERT_EVENT_KIND \
                        if incident_alert.get('ProductComponentName') == NRT_ALERT_TYPE_STRING \
                        else SCHEDULED_ALERT_EVENT_KIND

                events.extend(alert_events)

            else:
                # No events in the ASI alert - use the alert itself as the event
                product_value, product_fallback_field = find_fallback_value(
                    source_dicts=[incident_alert_flat, flat_incident],
                    fallbacks_list=product_field_fallback
                )
                if product_fallback_field is not None:
                    incident_alert_flat["product_type"] = product_value
                    if fallback_logic_debug:
                        incident_alert_flat["ProductFieldFallback"] = product_fallback_field

                incident_alert_flat["kind"] = NRT_ALERT_EVENT_KIND \
                        if incident_alert_flat.get('ProductComponentName') == NRT_ALERT_TYPE_STRING \
                        else SCHEDULED_ALERT_EVENT_KIND
                events.append(incident_alert_flat)
        else:
            # Use the alert itself as the event
            events.append(dict_to_flat(incident_alert.to_event()))
            entities_to_events = incident_alert.entities or []

            for entity in entities_to_events:
                if entity.kind not in ["Account", "Mailbox", "Host", "Ip"]:
                    continue

                entity.raw_data[entity.kind] = entity.get_value()
                for key, value in incident_alert.raw_data['properties'].items():
                    if isinstance(value, str) and is_date(value):
                        entity.raw_data['properties'][key] = value

                entity_flat = dict_to_flat(entity.raw_data)
                product_value, product_fallback_field = find_fallback_value(
                    source_dicts=[entity_flat, flat_incident],
                    fallbacks_list=product_field_fallback
                )
                if product_fallback_field is not None:
                    entity_flat["product_type"] = product_value
                    if fallback_logic_debug:
                        entity_flat["ProductFieldFallback"] = product_fallback_field

                events.append(entity_flat)

    alert_info.environment = environment_common.get_environment(dict_to_flat(alert.raw_data))
    alert_info.events = events

    for event in alert_info.events:
        for item in event_field_fallback:
            if event.get(item):
                event['event_type'] = event[item]
                if fallback_logic_debug:
                    event["EventFieldFallback"] = item
                break

        event_start_time = alert.properties.created_time_utc
        event_end_time = alert.properties.created_time_utc
        for item in start_time_fallback:
            if event.get(item):
                event_start_time = event[item]
                if fallback_logic_debug:
                    event["StartTimeFallback"] = item
                break
        for item in end_time_fallback:
            if event.get(item):
                event_end_time = event[item]
                if fallback_logic_debug:
                    event["EndTimeFallback"] = item
                break

        if event_start_time:
            event['Siemplify_Start_Time'] = event_start_time
            if fallback_logic_debug and not event.get("StartTimeFallback"):
                event["StartTimeFallback"] = "CreatedTimeUTC"
        else:
            event['Siemplify_Start_Time'] = utc_now().isoformat()
            if fallback_logic_debug:
                event["StartTimeFallback"] = "Current time"

        if event_end_time:
            event['Siemplify_End_Time'] = event_end_time
            if fallback_logic_debug and not event.get("EndTimeFallback"):
                event["EndTimeFallback"] = "CreatedTimeUTC"
        else:
            event['Siemplify_End_Time'] = utc_now().isoformat()
            if fallback_logic_debug:
                event["EndTimeFallback"] = "Current time"

    return alert_info


def pass_whitelist_filter(siemplify, alert, whitelist, whitelist_filter_type):
    # whitelist filter
    if whitelist:
        alert_title = " ".join(alert.properties.title.split()) if alert.properties.title else ""
        alert_title = handle_special_characters(alert_title)

        if whitelist_filter_type == BLACKLIST_FILTER and alert_title in whitelist:
            siemplify.LOGGER.info("Incident with title: \"{}\" did not pass blacklist filter."
                                  .format(alert.properties.title))
            return False

        if whitelist_filter_type == WHITELIST_FILTER and alert_title not in whitelist:
            siemplify.LOGGER.info("Incident with title: \"{}\" did not pass whitelist filter."
                                  .format(alert.properties.title))
            return False

    return True


if __name__ == "__main__":
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test_run)
