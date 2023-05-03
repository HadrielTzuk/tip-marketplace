import sys
from datetime import timedelta

from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyUtils import output_handler, convert_string_to_datetime
from SymantecATPManager import SymantecATPManager
from EnvironmentCommon import GetEnvironmentCommonFactory
from TIPCommon import (
    extract_connector_param,
    utc_now,
    unix_now,
    convert_comma_separated_to_list,
    read_ids,
    filter_old_alerts,
    is_approaching_timeout,
    write_ids,
    validate_timestamp,
    siemplify_fetch_timestamp,
    siemplify_save_timestamp
)

from validators import SymantecATPValidator
from constants import (
    INCIDENTS_CONNECTOR_NAME,
    WHITELIST_FILTER,
    BLACKLIST_FILTER,
    ATP_QUERIES_TIME_FORMAT,
    ACCEPTABLE_TIME_INTERVAL_IN_MINUTES,
    ALERT_ID_FIELD,
    LIMIT_IDS_IN_IDS_FILE
)


@output_handler
def main(is_test_run):
    connector_starting_time = unix_now()
    incidents = []
    all_incidents = []
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = INCIDENTS_CONNECTOR_NAME

    if is_test_run:
        siemplify.LOGGER.info(u'***** This is an \"IDE Play Button\" \"Run Connector once\" test run ******')

    siemplify.LOGGER.info(u'==================== Main - Param Init ====================')

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

    api_root = extract_connector_param(
        siemplify,
        param_name=u'API Root',
        input_type=unicode,
        is_mandatory=True,
        print_value=True
    )

    client_id = extract_connector_param(
        siemplify,
        param_name=u'Client ID',
        input_type=unicode,
        is_mandatory=True,
        print_value=False
    )

    client_secret = extract_connector_param(
        siemplify,
        param_name=u'Client Secret',
        input_type=unicode,
        is_mandatory=True,
        print_value=False
    )

    priorities_str = extract_connector_param(
        siemplify,
        param_name=u'Priority Filter',
        input_type=unicode,
        is_mandatory=True,
        print_value=True
    )

    offset_hours = extract_connector_param(
        siemplify,
        param_name=u'Fetch Max Hours Backwards',
        input_type=int,
        is_mandatory=False,
        print_value=True
    )

    limit = extract_connector_param(
        siemplify,
        param_name=u'Max Incidents To Fetch',
        input_type=int,
        is_mandatory=False,
        print_value=True
    )

    whitelist_as_blacklist = extract_connector_param(
        siemplify,
        param_name=u'Use whitelist as a blacklist',
        input_type=bool,
        is_mandatory=True,
        print_value=True
    )

    verify_ssl = extract_connector_param(
        siemplify,
        param_name=u'Use SSL',
        input_type=bool,
        is_mandatory=True,
        print_value=True
    )

    python_process_timeout = extract_connector_param(
        siemplify,
        param_name=u'PythonProcessTimeout',
        input_type=int,
        is_mandatory=True,
        print_value=True
    )

    priorities = convert_comma_separated_to_list(priorities_str)
    SymantecATPValidator.validate_priorities(priorities)
    whitelist_as_blacklist = BLACKLIST_FILTER if whitelist_as_blacklist else WHITELIST_FILTER

    siemplify.LOGGER.info(u'------------------- Main - Started -------------------')

    environment_common = GetEnvironmentCommonFactory.create_environment_manager(
        siemplify=siemplify,
        environment_field_name=environment,
        environment_regex_pattern=environment_regex
    )

    if is_test_run:
        siemplify.LOGGER.info(u'This is a test run. Ignoring stored timestamps')
        last_success_time_datetime = validate_timestamp(
            utc_now() - timedelta(hours=offset_hours), offset_hours
        )
    else:
        last_success_time_datetime = validate_timestamp(
            siemplify_fetch_timestamp(siemplify, datetime_format=True),
            offset_hours
        )

    # Read already existing alerts ids
    existing_ids = read_ids(siemplify=siemplify)

    try:
        client = SymantecATPManager(
            api_root=api_root,
            client_id=client_id,
            client_secret=client_secret,
            verify_ssl=verify_ssl
        )

        if is_test_run:
            siemplify.LOGGER.info(u'This is a TEST run. Only 1 alert will be processed.')
            limit = 1

        fetched_incidents = client.get_incidents(
            priorities=priorities,
            last_event_seen=last_success_time_datetime,
            limit=limit
        )

        siemplify.LOGGER.info(
            u'{} incidents were fetched from timestamp {}'
            .format(len(fetched_incidents), last_success_time_datetime)
        )

        filtered_incidents = filter_old_alerts(siemplify=siemplify,
                                               alerts=fetched_incidents,
                                               existing_ids=existing_ids,
                                               id_key=ALERT_ID_FIELD)
        siemplify.LOGGER.info(
            u'Found {} new incidents in since {}.'
            .format(len(filtered_incidents), last_success_time_datetime.isoformat())
        )
        filtered_incidents = [client.fetch_events_for_incident(incident) for incident in filtered_incidents]
        filtered_incidents = sorted(filtered_incidents, key=lambda inc: inc.last_event_seen)
    except Exception as e:
        siemplify.LOGGER.error(unicode(e))
        siemplify.LOGGER.exception(e)
        sys.exit(1)

    for incident in filtered_incidents:
        try:
            if is_approaching_timeout(python_process_timeout=python_process_timeout,
                                      connector_starting_time=connector_starting_time):
                siemplify.LOGGER.info(u'Timeout is approaching. Connector will gracefully exit.')
                break

            if len(incidents) >= limit:
                siemplify.LOGGER.info(u'Stop processing alerts, limit {} reached'.format(limit))
                break

            siemplify.LOGGER.info(u'Processing incident {}'.format(incident.uuid))

            if not incident.pass_time_filter():
                siemplify.LOGGER.info(
                    u'Incident {} is newer than {} minutes. Stopping connector...'
                    .format(incident.uuid, ACCEPTABLE_TIME_INTERVAL_IN_MINUTES)
                )
                # Breaking connector loop because next incident can pass acceptable time
                # and we can lose incidents that did not pass before in one loop
                break

            all_incidents.append(incident)
            existing_ids.append(incident.uuid)

            if not incident.pass_whitelist_or_blacklist_filter(siemplify.whitelist, whitelist_as_blacklist):
                siemplify.LOGGER.info(
                    u'Incident with id: {} and name: {} did not pass {} filter. Skipping...'
                    .format(incident.uuid, incident.rule_name, whitelist_as_blacklist)
                )
                continue

            is_overflowed = False
            siemplify.LOGGER.info(u'Started creating Alert {}'.format(incident.uuid),
                                  alert_id=incident.uuid)
            incident_info = incident.to_alert(environment_common)
            siemplify.LOGGER.info(
                u'Finished creating Alert {}'
                .format(incident.uuid),
                alert_id=incident.uuid
            )

            try:
                is_overflowed = siemplify.is_overflowed_alert(
                    environment=incident_info.environment,
                    alert_identifier=incident_info.ticket_id,
                    alert_name=incident_info.rule_generator,
                    product=incident_info.device_product
                )

            except Exception as e:
                siemplify.LOGGER.error(u'Error validation connector overflow, ERROR: {}'.format(e))
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            if is_overflowed:
                siemplify.LOGGER.info(
                    u'{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping.'
                    .format(
                        alert_name=incident_info.rule_generator,
                        alert_identifier=incident_info.ticket_id,
                        environment=incident_info.environment,
                        product=incident_info.device_product
                    )
                )
                continue
            else:
                incidents.append(incident_info)
                siemplify.LOGGER.info(u'Incident {} was created.'.format(incident.uuid))

        except Exception as e:
            siemplify.LOGGER.error(u'Failed to process incident {}'.format(incident.uuid), alert_id=incident.uuid)
            siemplify.LOGGER.exception(e)

            if is_test_run:
                raise

    if not is_test_run:
        if all_incidents:
            new_timestamp = convert_string_to_datetime(all_incidents[-1].last_event_seen)
            siemplify_save_timestamp(siemplify=siemplify, new_timestamp=new_timestamp)
            siemplify.LOGGER.info(
                u'New timestamp {} has been saved'
                .format(new_timestamp.strftime(ATP_QUERIES_TIME_FORMAT))
            )

        write_ids(siemplify=siemplify, ids=existing_ids, stored_ids_limit=LIMIT_IDS_IN_IDS_FILE)

    siemplify.LOGGER.info(u'Incidents Processed: {} of {}'.format(len(incidents), len(all_incidents)))
    siemplify.LOGGER.info(u'Created total of {} incidents'.format(len(incidents)))

    siemplify.LOGGER.info(u'------------------- Main - Finished -------------------')
    siemplify.return_package(incidents)


if __name__ == '__main__':
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test_run)
