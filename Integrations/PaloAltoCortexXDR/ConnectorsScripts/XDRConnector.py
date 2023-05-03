# ==============================================================================
# title           :XDRConnector.py
# description     :This Module contain all Palo alto cortex XDR API logic.
# author          :zivh@siemplify.co
# date            :08-08-2019
# python_version  :2.7
# libraries       : -
# requirements    :
# product_version : 1.0
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
from SiemplifyConnectors import SiemplifyConnectorExecution, CaseInfo
from XDRManager import XDRManager, CortexSortTypesEnum, CortexSortOrderEnum, CortexCreationFilterEnum
import sys
import os
import json
from SiemplifyUtils import convert_datetime_to_unix_time, dict_to_flat
from enum import Enum
import datetime
from SiemplifyUtils import utc_now
from EnvironmentCommon import EnvironmentHandle

# =====================================
#             CONSTANTS               #
# =====================================
# Generic Consts.
PRODUCT = 'Cortex XDR'
VENDOR = 'Palo Alto'

DEFAULT_NAME = "Palo Alto Cortex XDR Incident"
DEFAULT_EVENT_NAME = "Palo Alto Cortex XDR Incident Artifact"


class XDRPriorityEnum(Enum):
    HIGH = "high"
    MED = "medium"
    LOW = "low"


class SiemplifyPriorityEnum(Enum):
    HIGH = 80
    MED = 60
    LOW = 40


# Priorities Map.
PRIORITIES_MAP = {
    XDRPriorityEnum.HIGH: SiemplifyPriorityEnum.HIGH,
    XDRPriorityEnum.MED: SiemplifyPriorityEnum.MED,
    XDRPriorityEnum.LOW: SiemplifyPriorityEnum.LOW,
}

ALERTS_LIMIT = 20
DEFAULT_DAYS_BACKWARDS = 3
INCIDENT_ID_FILE = 'IncidentsIDs.json'
MAP_FILE = 'map.json'


# =====================================
#              CLASSES                #
# =====================================


class CortexXDRConnectorException(Exception):
    """
    Palo alto Cortex connector Exception
    """
    pass


def main(is_test_run=False):
    siemplify = SiemplifyConnectorExecution()
    alerts = []
    all_alerts = []

    try:
        # Parameters.
        siemplify.LOGGER.info("==================== Main - Param Init ====================")
        api_root, api_key, api_key_id, verify_ssl, environment_field_name, environment_regex, alerts_count_limit, max_days_backwards, map_file = init_params(
            siemplify)

        if is_test_run:
            siemplify.LOGGER.info("***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******")
        else:
            siemplify.LOGGER.info('=============== Starting XDR Connector ===============')

        # Manager Definition.
        siemplify.LOGGER.info("Connecting to PaloAlto Cortex XDR")
        xdr_manager = XDRManager(api_root, api_key, api_key_id, verify_ssl, siemplify.LOGGER)
        siemplify.LOGGER.info('Successfully connected to PaloAlto Cortex XDR.')

        environment_common = EnvironmentHandle(map_file, siemplify.LOGGER, environment_field_name, environment_regex,
                                               siemplify.context.connector_info.environment)

        # Fix first time run
        last_run_time = siemplify.fetch_timestamp(datetime_format=True)
        last_calculated_run_time = validate_timestamp(last_run_time, max_days_backwards)
        siemplify.LOGGER.info(
            "Calculating last run time. Last run time is: {0}".format(last_calculated_run_time))

        # fetch last fetched incident index
        previous_incidents_ids = fetch_incident_ids(siemplify,
                                                    os.path.join(siemplify.run_folder, INCIDENT_ID_FILE))

        search_time = convert_datetime_to_unix_time(last_calculated_run_time)
        siemplify.LOGGER.info("Fetching incidents from {0}".format(last_calculated_run_time))
        incidents = fetch_incidents(xdr_manager, siemplify, search_time, alerts_count_limit, previous_incidents_ids)
        siemplify.LOGGER.info("Found {0} incidents".format(len(incidents)))

        if is_test_run:
            incidents = incidents[:1]

        for incident in incidents:
            alert_id = incident.get('incident', {}).get('incident_id')
            try:
                # Create alert info
                siemplify.LOGGER.info(
                    "---------- Converting Incident {0} to Siemplify Alert ----------".format(alert_id))
                alert = create_alert_info(siemplify, incident, environment_common)

                is_overflow = False
                try:
                    # Check if alert overflow
                    is_overflow = siemplify.is_overflowed_alert(
                        environment=alert.environment,
                        alert_identifier=str(alert.ticket_id),
                        alert_name=str(alert.rule_generator),
                        product=str(alert.device_product)
                    )
                except Exception as e:
                    siemplify.LOGGER.error("Check if alert is overflow failed. Error: {0}.".format(e))

                if is_overflow:
                    # Skipping this alert (and dot ingest it to siemplify)
                    siemplify.LOGGER.info(
                        "{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping"
                            .format(alert_name=str(alert.rule_generator),
                                    alert_identifier=str(alert.ticket_id),
                                    environment=alert.environment,
                                    product=str(alert.device_product)))
                else:
                    # Ingest the alert to siemplify
                    alerts.append(alert)

                siemplify.LOGGER.info(
                    "---------- Finished processing Alert {0} ----------".format(alert_id))
                all_alerts.append(alert)

            except Exception as e:
                siemplify.LOGGER.error("Failed to convert incident {0} to Siemplfiy alert".format(alert_id))
                siemplify.LOGGER.error("Error Message: {}".format(e.message))
                siemplify.LOGGER.exception(e)
                if is_test_run:
                    raise

        siemplify.LOGGER.info("Completed processing incidents.")

        # Get last successful execution time.
        if all_alerts:
            # Sort the cases by the start time of each case.
            all_alerts_sorted = sorted(all_alerts, key=lambda case: case.start_time)
            # Last execution time is set to the newest incident time
            new_last_run_time = all_alerts_sorted[-1].start_time
        else:
            # last_calculated_run_time is datetime object. Convert it to milliseconds timestamp.
            new_last_run_time = convert_datetime_to_unix_time(last_calculated_run_time)

        if not is_test_run:
            # update last execution time
            siemplify.save_timestamp(new_timestamp=new_last_run_time)

            # save to index file according to fetch incidents from this place in the next cycle
            siemplify.LOGGER.info(
                "Update last execution time and save the ids to {0} file".format(INCIDENT_ID_FILE))
            last_incidents_ids = [incident.get('incident', {}).get('incident_id') for incident in incidents]
            if last_incidents_ids:
                write_incident_ids(siemplify, os.path.join(siemplify.run_folder, INCIDENT_ID_FILE),
                                   last_incidents_ids)

        # Return data
        siemplify.LOGGER.info("Created {} cases.".format(len(alerts)))
        siemplify.LOGGER.info("=============== Main - Cortex XDR Connector Finish ===============")
        siemplify.return_package(alerts)

    except Exception as e:
        siemplify.LOGGER.error(e.message)
        siemplify.LOGGER.exception(e)


def init_params(siemplify):
    """
    initialize params
    :param siemplify: {SiemplifyConnectorExecution}
    :return: params
    """
    api_root = siemplify.parameters.get('Api Root')
    api_key = siemplify.parameters.get('Api Key')
    api_key_id = int(siemplify.parameters.get('Api Key ID'))
    verify_ssl = str(siemplify.parameters.get('Verify SSL', 'False')).lower() == 'true'

    environment_field_name = siemplify.parameters.get('Environment Field Name')
    environment_regex = siemplify.parameters.get('Environment Regex Pattern')
    alerts_count_limit = int(
        siemplify.parameters.get('Alerts Count Limit')) if siemplify.parameters.get(
        'Alerts Count Limit') else ALERTS_LIMIT
    max_days_backwards = int(siemplify.parameters.get(
        'Max Days Backwards')) if siemplify.parameters.get(
        'Max Days Backwards') else DEFAULT_DAYS_BACKWARDS

    map_file = os.path.join(siemplify.run_folder, MAP_FILE)
    try:
        if not os.path.exists(map_file):
            with open(map_file, 'w+') as map_file:
                map_file.write(json.dumps(
                    {"Original environment name": "Desired environment name",
                     "Env1": "MyEnv1"}))
                siemplify.LOGGER.info(
                    "Mapping file was created at {}".format(unicode(map_file).encode("utf-8")))
    except Exception as e:
        siemplify.LOGGER.error("Unable to create mapping file: {}".format(str(e)))
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(
        "Api Root: {0}, Api Key ID: {1}, \nEnvironment Field Name: {2}, Environment Regex Pattern:{3}"
        " \nAlerts Limit: {4}, Max Days Backwards: {5}".format(
            api_root, api_key_id, environment_field_name, environment_regex, alerts_count_limit,
            max_days_backwards))
    return api_root, api_key, api_key_id, verify_ssl, environment_field_name, environment_regex, alerts_count_limit, max_days_backwards, map_file


def fetch_incidents(xdr_manager, siemplify, search_time, max_alerts_per_cycle, incidents_ids=None):
    """
    Fetch incidents from Cortex XDR (Incidents = Alerts at Siemplify)
    :param search_time: {unix time} last incident time - used to fetch new incidents after this time
    :param max_alerts_per_cycle: {int} limit the returned incidents
    :param incidents_ids: {list} of the incidents ids from previous cycle
    :return: {list} of Incidents {dict} with extra data - including the alerts(events in Siemplify)
    """
    incidents = []
    # Always search from 0 because we are fetching be time
    # Search to param is used for limit the results
    # this is the calculation of the Offset within the result set after which you do not want incidents returned.
    all_incidents = xdr_manager.get_incidents(creation_time=search_time,
                                              creation_filter_enum=CortexCreationFilterEnum.GTE_CREATION_TIME,
                                              search_from=0,
                                              search_to=max_alerts_per_cycle,
                                              sort_order=CortexSortOrderEnum.SORT_BY_ASC_ORDER,
                                              sort_type=CortexSortTypesEnum.SORT_BY_CREATION_TIME)

    for incident in all_incidents:
        # validate the alert not already fetch
        fetch_incident = not incidents_ids or incident.get('incident_id') not in incidents_ids
        if fetch_incident:
            try:
                siemplify.LOGGER.info("Fetching incident {0} data".format(incident.get('incident_id')))
                incident_extra_data = xdr_manager.get_extra_incident_data(incident.get('incident_id'))
                incidents.append(incident_extra_data)
            except Exception as e:
                # continue if an incident data fetching has failed
                siemplify.LOGGER.error("Fetching incident {0} data has failed".format(incident.get('incident_id')))
                siemplify.LOGGER.exception(str(e))
        else:
            siemplify.LOGGER.info("Incident {0} has been fetched".format(incident.get('incident_id')))

    return incidents


def create_alert_info(siemplify, alert, environment_common):
    """
    Builds a case object from Cortex XDR alert
    :param alert: {dict} alert info
    :return: {CaseInfo} The newly created case
    """
    alert_id = alert.get('incident', {}).get('incident_id')
    alert_info = CaseInfo()
    alert_info.start_time = alert.get('incident', {}).get('creation_time', 1)
    alert_info.end_time = alert.get('incident', {}).get('modification_time', 1)

    events = get_events(siemplify, alert, alert_info.start_time, alert_info.end_time)

    alert_info.name = alert.get('incident', {}).get('description', DEFAULT_NAME)
    alert_info.ticket_id = alert_id
    alert_info.display_id = alert_id
    alert_info.identifier = alert_id
    if events:
        alert_info.rule_generator = events[0].get('source', PRODUCT)
    else:
        alert_info.rule_generator = PRODUCT
    alert_info.device_product = PRODUCT
    alert_info.device_vendor = VENDOR
    alert_info.priority = calculate_priority(alert.get('incident', {}).get('severity'))
    alert_info.events = events

    environment = environment_common.get_environment(alert.get('incident', {}))
    if environment:
        alert_info.environment = environment
    else:
        alert_info.environment = siemplify.context.connector_info.environment

    return alert_info


def calculate_priority(xdr_incident_severity):
    """
    The function calculates case priority by the Priority Map.
    :param xdr_incident_severity: {string} severity value as it came from the cortex XDR
    :return: calculated Siemplify alarm priority {integer}
    """
    for xdr_priority, siemplify_priority in PRIORITIES_MAP.items():
        if xdr_incident_severity == xdr_priority.value:
            return siemplify_priority.value
    # return low
    return SiemplifyPriorityEnum.LOW


def get_events(siemplify, incident_data, parent_start_time, parent_end_time):
    """
    cretae events list
    :param incident_data: {dict} alert extra details - including incident data, alerts data
    :return: {list} of events
    """
    events_details = []
    alert_id = incident_data.get('incident', {}).get('incident_id')
    siemplify.LOGGER.info("-------- Events fetching started for alert {} --------".format(alert_id))
    try:
        # alerts + artifacts = events in Siemplify
        file_artifacts = incident_data.get('file_artifacts', {}).get('data', [])
        network_artifacts = incident_data.get('network_artifacts', {}).get('data', [])
        alerts = incident_data.get('alerts', {}).get('data', [])

        events = alerts
        events.extend(file_artifacts)
        events.extend(network_artifacts)

        siemplify.LOGGER.info("---- Found {0} events (XDR Alerts)----".format(len(alerts)))
        siemplify.LOGGER.info(
            "---- Found {0} File Artifacts And {1} Network Artifacts (Adding them as events)----".format(
                len(file_artifacts), len(network_artifacts)))

        for event in events:
            try:
                event_details = dict_to_flat(event)
                event_details['event_name'] = event.get('name', DEFAULT_EVENT_NAME)
                event_details['parent_start_time'] = parent_start_time
                event_details['parent_end_time'] = parent_end_time
                events_details.append(event_details)
            except Exception as e:
                siemplify.LOGGER.logger.error("Failed to get event {0}".format(event.get("name")))
                siemplify.LOGGER.logger.exception(str(e))

    except Exception as e:
        siemplify.LOGGER.logger.error(
            "Unable to get events for Incident {}".format(incident_data.get('incident', {}).get('incident_id')))
        siemplify.LOGGER.logger.exception(str(e))

    siemplify.LOGGER.info("-------- Events fetching finished for alert {} --------".format(alert_id))
    return events_details


def fetch_incident_ids(siemplify, incidents_ids_path):
    """
    Get the incidents ids from previous cycle
    to avoid double inserting of the same incident
    :param incidents_ids_path: {string} incidents ids path
    :return: {list} of incidents ids
    """
    if not os.path.exists(incidents_ids_path):
        return []

    try:
        with open(incidents_ids_path, 'r') as f:
            return json.loads(f.read())
    except Exception as e:
        siemplify.LOGGER.error("Unable to fetch incidents ids")
        siemplify.LOGGER.exception(e)
        return []


def write_incident_ids(siemplify, incidents_ids_path, incidents_ids):
    """
    Write ids to the ids file
    :param incidents_ids_path: {str} The path of the existing incident ids file.
    :param incidents_ids: {list} The ids to write to the file
    """
    if not os.path.exists(os.path.abspath(os.path.dirname(incidents_ids_path))):
        os.makedirs(os.path.dirname(incidents_ids_path))

    with open(incidents_ids_path, 'w') as incident_ids_data_file:
        try:
            for chunk in json.JSONEncoder().iterencode(incidents_ids):
                incident_ids_data_file.write(chunk)
        except Exception as e:
            siemplify.LOGGER.error("Failed to write incident ids to {}.".format(incidents_ids_path))
            siemplify.LOGGER.exception(e)
            try:
                # Move seeker to start of the file
                incident_ids_data_file.seek(0)
                # Empty the content of the file (the partially written content that was written before the exception)
                incident_ids_data_file.truncate()
                # Write an empty list
                incident_ids_data_file.write("[]")
            except Exception as e:
                siemplify.LOGGER.error(
                    "Failed to empty the file after failure in writing the incident ids to {}.".format(
                        incidents_ids_path))
                siemplify.LOGGER.exception(e)


def validate_timestamp(last_run_timestamp, offset):
    """
    Validate timestamp in range
    :param last_run_timestamp: {datetime} last run timestamp
    :param offset: {datetime} last run timestamp
    :return: {datetime} if first run, return current time minus offset time, else return timestamp from file
    """
    current_time = utc_now()
    # Check if first run
    if current_time - last_run_timestamp > datetime.timedelta(days=offset):
        return current_time - datetime.timedelta(days=offset)
    else:
        return last_run_timestamp


if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test_run)
