from SiemplifyUtils import output_handler
from SiemplifyConnectors import SiemplifyConnectorExecution, CaseInfo
from SiemplifyUtils import convert_string_to_unix_time, utc_now, unix_now
from TIPCommon import extract_connector_param, validate_map_file
from EnvironmentCommon import EnvironmentHandle
from utils import write_ids, read_ids, save_timestamp, is_overflowed
from SentinelOneV2Factory import SentinelOneV2ManagerFactory, API_VERSION_2_0
from exceptions import SentinelOneV2BadRequestError
import uuid
import sys
import datetime
import os

# CONSTANTS
MAP_FILE = "map.json"
IDS_FILE = "ids.json"
DEFAULT_PRODUCT = 'SentinelOneV2'

ALERT_WITHOUT_A_RULE_DEFAULT = 'Alert has no rule.'
ALERT_WITHOUT_A_DESCRIPTION_DEFAULT = 'Alert has no description.'
ALERT_WITHOUT_A_NAME_DEFAULT = 'Alert has no name.'
THREAT_NAME_IS_EMPTY_DEFAULT = "Threat name is empty."

WHITELIST_FILTER = 'whitelist'
BLACKLIST_FILTER = 'blacklist'

HOURS_LIMIT_IN_IDS_FILE = 72
MAX_EVENTS_LIMIT = 199


class SentinelOneV2ThreatsConnector(object):
    def __init__(self, connector_scope, environment_field_name, environment_regex):
        self.connector_scope = connector_scope
        self.logger = connector_scope.LOGGER

        map_file_path = os.path.join(connector_scope.run_folder, MAP_FILE)

        connector_scope.LOGGER.info("Validating environments mapping file at: {}".format(map_file_path))
        validate_map_file(connector_scope, map_file_path)

        connector_scope.LOGGER.info("Loading EnvironmentCommon")
        self.environment_common = EnvironmentHandle(map_file_path, self.logger, environment_field_name,
                                                    environment_regex,
                                                    connector_scope.context.connector_info.environment)

    @staticmethod
    def validate_timestamp_offset(datetime_timestamp, offset_in_days=2):
        """
        Validate if timestamp in offset range.
        :param datetime_timestamp: {datetime} timestamp that were fetched from the timestamp file
        :param offset_in_days: {str} the offset in days to validate
        :return: unix time: {int} if time not in offset return offset time
        """
        offset_datetime = utc_now() - datetime.timedelta(days=offset_in_days)

        if datetime_timestamp <= offset_datetime:
            return offset_datetime
        return datetime_timestamp

    def convert_threat_time_to_unixtime(self, string_time):
        """
        Convert threat time from string format to unix time.
        :param string_time: {str} Time string.
        :return: {long} Time unix time.
        """
        try:
            return convert_string_to_unix_time(string_time)
        except Exception as err:
            error_message = "Failed to convert threat time, ERROR: {0}".format(err)
            self.logger.error(error_message)
            self.logger.exception(err)
            return 1

    def create_case(self, threat, device_product_field, threat_events):
        """
        Create a case object.
        :param threat: {Threat} Threat object
        :param device_product_field: {str} property name
        :param threat_events: {list} List of ThreatEvent objects
        :return: {CaseInfo} Case object.
        """

        def to_events(threat_json, alert_events):
            events = [threat_json]
            for event in alert_events:
                flat_event = event.to_flat()
                flat_event["siemplify_event"] = "SentinelOne Event"
                events.append(flat_event)

            return events

        threat_flat_json = threat.to_flat()

        case_info = CaseInfo()
        case_info.start_time = case_info.end_time = self.convert_threat_time_to_unixtime(threat.created_at)
        case_info.rule_generator = threat.classification or ALERT_WITHOUT_A_RULE_DEFAULT
        case_info.device_product = threat_flat_json.get(device_product_field, DEFAULT_PRODUCT) or DEFAULT_PRODUCT
        case_info.device_vendor = case_info.device_product
        case_info.environment = self.environment_common.get_environment(threat_flat_json)
        case_info.name = threat.threat_name or THREAT_NAME_IS_EMPTY_DEFAULT
        # If no Session ID, replace with timestamp + uuid because timestamp can be not unique in some cases.
        case_info.ticket_id = threat.threat_id or '{0}_{1}'.format(case_info.start_time, uuid.uuid4())
        case_info.display_id = case_info.identifier = case_info.ticket_id
        case_info.description = threat.description or ALERT_WITHOUT_A_DESCRIPTION_DEFAULT
        case_info.events = to_events(threat_flat_json, threat_events)

        self.logger.info("AlertInfo name: {}".format(case_info.name))
        self.logger.info("AlertInfo time: {} ({})".format(case_info.start_time, threat.created_at))
        self.logger.info("AlertInfo environment: {}".format(case_info.environment))
        self.logger.info("AlertInfo identifier: {}".format(case_info.ticket_id))
        self.logger.info("AlertInfo description: {}".format(case_info.description))

        return case_info

    @staticmethod
    def pass_whitelist_or_blacklist_filter(threat, whitelist, whitelist_filter_type):
        """
        Determine whether threat pass the whitelist/blacklist filter or not.
        :param threat: {Threat} The thread object.
        :param whitelist: {list} The whitelist provided by user.
        :param whitelist_filter_type: {str} whitelist filter type. Possible values are WHITELIST_FILTER, BLACKLIST_FILTER
        :return: {bool} Whether threat pass the whitelist/blacklist filter or not.
        """
        if not whitelist:
            return True

        alert_name = threat.threat_name

        if whitelist_filter_type == BLACKLIST_FILTER:
            return alert_name not in whitelist

        return alert_name in whitelist


@output_handler
def main(test_handler=False):
    connector_scope = SiemplifyConnectorExecution()
    output_variables = {}
    log_items, cases, fetched_threats = [], [], []

    try:
        if test_handler:
            connector_scope.LOGGER.info(" ------------ Starting SentinelOneV2 Threats Connector test. ------------ ")
        else:
            connector_scope.LOGGER.info(" ------------ Starting Connector. ------------ ")

        api_root = extract_connector_param(connector_scope, param_name="API Root", is_mandatory=True)
        api_version = extract_connector_param(connector_scope, param_name="API Version", print_value=True,
                                              default_value=API_VERSION_2_0)
        api_token = extract_connector_param(connector_scope, param_name="API Token", is_mandatory=True)
        verify_ssl = extract_connector_param(connector_scope, param_name="Verify SSL", is_mandatory=True,
                                             input_type=bool)
        whitelist_as_a_blacklist = extract_connector_param(connector_scope, param_name="Use whitelist as a blacklist",
                                                           is_mandatory=True, input_type=bool)
        whitelist_filter_type = BLACKLIST_FILTER if whitelist_as_a_blacklist else WHITELIST_FILTER
        max_days_backwards = extract_connector_param(connector_scope, param_name="Fetch Max Days Backwards",
                                                     default_value=1, input_type=int, print_value=True)
        fetch_limit = extract_connector_param(connector_scope, param_name='Max Alerts Per Cycle', input_type=int)
        device_product_field = extract_connector_param(connector_scope, param_name="DeviceProductField",
                                                       is_mandatory=True)
        environment_field_name = extract_connector_param(connector_scope, param_name="Environment Field Name",
                                                         print_value=True)
        environment_regex = extract_connector_param(connector_scope, param_name="Environment Regex Pattern",
                                                    print_value=True)
        event_object_type_filter = extract_connector_param(connector_scope, param_name="Event Object Type Filter",
                                                           is_mandatory=False)
        event_type_filter = extract_connector_param(connector_scope, param_name="Event Type Filter",
                                                    is_mandatory=False)
        events_limit = extract_connector_param(connector_scope, param_name='Max Events To Return', input_type=int)
        whitelist = connector_scope.whitelist

        if events_limit and events_limit > MAX_EVENTS_LIMIT:
            connector_scope.LOGGER.info(f'Maximum allowed number of events to return is {MAX_EVENTS_LIMIT}. '
                                        f'Setting the value to the default: {MAX_EVENTS_LIMIT}')
            events_limit = MAX_EVENTS_LIMIT

        event_object_type_filter = event_object_type_filter.replace(' ', '').lower() if event_object_type_filter else \
            event_object_type_filter
        event_type_filter = event_type_filter.replace(' ', '').upper() if event_type_filter else event_type_filter

        sentinel_manager = SentinelOneV2ManagerFactory(api_version).get_manager(api_root=api_root, api_token=api_token,
                                                                                verify_ssl=verify_ssl)

        sentinel_connector = SentinelOneV2ThreatsConnector(connector_scope, environment_field_name, environment_regex)

        last_run_time = sentinel_connector.validate_timestamp_offset(
            connector_scope.fetch_timestamp(datetime_format=True),
            max_days_backwards)

        # Read already existing alerts ids
        connector_scope.LOGGER.info("Loading existing ids from IDS file.")
        existing_ids = read_ids(connector_scope, max_hours_backwards=HOURS_LIMIT_IN_IDS_FILE)
        connector_scope.LOGGER.info('Found {} existing ids in ids.json'.format(len(existing_ids)))

        connector_scope.LOGGER.info('Fetching threats since {}'.format(last_run_time.isoformat()))
        threats = sentinel_manager.get_unresolved_threats_by_time(last_run_time, list(existing_ids.keys()),
                                                                  limit=fetch_limit)

        connector_scope.LOGGER.info("Found {} new threats.".format(len(threats)))

        if test_handler:
            threats = threats[-1:]

        for threat in threats:
            try:
                connector_scope.LOGGER.info("Processing threat {} ({})".format(threat.threat_id,
                                                                                              threat.threat_name))
                connector_scope.LOGGER.info("Checking if threat {} is valid by {}".format(threat.threat_id,
                                                                                          whitelist_filter_type))

                fetched_threats.append(threat)

                if not sentinel_connector.pass_whitelist_or_blacklist_filter(threat, whitelist, whitelist_filter_type):
                    connector_scope.LOGGER.info("Threat with id: {} and name: {} did not pass {} filter. Skipping..."
                                                .format(threat.threat_id, threat.threat_name, whitelist_filter_type))
                    existing_ids.update({threat.threat_id: unix_now()})
                    continue
                connector_scope.LOGGER.info("Fetching events for threat with id: {}".format(threat.threat_id))
                threat_events = sentinel_manager.get_threat_events(threat_id=threat.threat_id,
                                                                   event_types=event_object_type_filter,
                                                                   event_subtypes=event_type_filter,
                                                                   limit=events_limit)
                connector_scope.LOGGER.info("Found {} events for threat with id: {}.".format(len(threat_events),
                                                                                             threat.threat_id))
                connector_scope.LOGGER.info("Creating case for threat with id: {}".format(threat.threat_id))
                case = sentinel_connector.create_case(
                    threat,
                    device_product_field=device_product_field,
                    threat_events=threat_events
                )

                existing_ids.update({threat.threat_id: unix_now()})

                if is_overflowed(connector_scope, alert_info=case, is_test_run=test_handler):
                    connector_scope.LOGGER.info(
                        "{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping."
                        .format(alert_name=case.rule_generator,
                                alert_identifier=case.ticket_id,
                                environment=case.environment,
                                product=case.device_product))
                else:
                    cases.append(case)
                    connector_scope.LOGGER.info('Case with display id "{}" was created.'.format(case.display_id))

            except SentinelOneV2BadRequestError as err:
                connector_scope.LOGGER.error(
                    f'Error execution connector \"Threat Connector\". Reason: {err} Please check that '
                    f'all of the parameters are configured correctly. Especially, pay attention to '
                    f'spelling for parameters \"Event Object Type Filter\" and \"Event Type Filter\".')
                connector_scope.LOGGER.exception(err)
                if test_handler:
                    raise

            except Exception as err:
                error_message = "Failed creating case for threat with ID: {0}, ERROR: {1}".format(
                    threat.threat_id,
                    err
                )
                connector_scope.LOGGER.error(error_message)
                connector_scope.LOGGER.exception(err)

                if test_handler:
                    raise

        connector_scope.LOGGER.info("Created total of {} cases.".format(len(cases)))

        if not test_handler:
            save_timestamp(connector_scope, alerts=fetched_threats, timestamp_key='creation_time_unix_time')
            write_ids(connector_scope, ids=existing_ids, ids_file_name=IDS_FILE)

        if test_handler:
            connector_scope.LOGGER.info(" ------------ Complete SentinelOneV2 Threats Connector test. ------------ ")
        else:
            connector_scope.LOGGER.info(" ------------ Complete Connector Iteration. ------------ ")

        connector_scope.return_package(cases, output_variables, log_items)

    except Exception as err:
        connector_scope.LOGGER.error('Got exception on main handler. Error: {0}'.format(err))
        connector_scope.LOGGER.exception(err)
        if test_handler:
            raise


if __name__ == "__main__":
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == u'True')
    main(is_test)
