from SiemplifyUtils import output_handler
# ============================================================================#
# title           :ServiceNowConnector.py
# description     :This Module contain all ServiceNow connector functionality
# author          :zivh@siemplify.co
# date            :26-07-2018
# python_version  :3.7
# product_version: Jakarta
# Doc: https://developer.servicenow.com/app.do#!/rest_api_doc?v=jakarta&id=r_AggregateAPI-GET
# ============================================================================#

# ============================= IMPORTS ===================================== #
import sys
import arrow
from SiemplifyUtils import convert_string_to_datetime, convert_datetime_to_unix_time
from SiemplifyConnectors import CaseInfo, SiemplifyConnectorExecution
from ServiceNowManager import ServiceNowManager, DEFAULT_TABLE
from TIPCommon import extract_connector_param, dict_to_flat, siemplify_fetch_timestamp, siemplify_save_timestamp, \
    validate_timestamp, is_overflowed
from constants import INTEGRATION_NAME, CONNECTOR_NAME, PRODUCT_NAME, VENDOR, DEFAULT_DAYS_BACKWARDS,\
    MAX_INCIDENTS_PER_CYCLE, DEFAULT_NAME, CASE_RULE_GENERATOR, MSG_ID_ERROR_MSG, NO_RESULTS, SN_DEFAULT_DOMAIN,\
    DEFAULT_EVENT_NAME, LINK_KEY, PRIORITY_MAPPING, LOW_PRIORITY


# ============================= CLASSES ===================================== #

class ServiceNowConnector(object):

    def __init__(self, connector_scope, connector_name, sn_manager, max_incidents_per_cycle, server_time_zone,
                 whitelist, whitelist_as_blacklist):
        self.connector_scope = connector_scope
        self.connector_scope.script_name = connector_name
        self.logger = connector_scope.LOGGER
        self.sn_manager = sn_manager
        self.max_incidents_per_cycle = max_incidents_per_cycle
        self.server_time_zone = server_time_zone
        self.whitelist = self.get_whitelist_params(whitelist_pairs=whitelist)
        self.whitelist_as_blacklist = whitelist_as_blacklist

    def get_whitelist_params(self, whitelist_pairs):
        """
        Extract whitelist fields
        :param whitelist_pairs: {list} list of comma separated key values
        :return: {dict} of all extracted fields
        """
        result = {}
        for whitelist in whitelist_pairs:
            for field in whitelist.split(','):
                if '=' not in field:
                    result[field] = ''
                    continue
                key, value = field.split('=', 1)
                result[key.strip()] = value.strip()

        return result

    def get_whitelist_queries(self):
        """
        Get whitelist queries
        :return: {list} of whitelist queries or None
        """
        operator = '!=' if self.whitelist_as_blacklist else '='

        return self.prepare_whitelist_params_as_query(whitelist_params=self.whitelist, operator=operator)

    def prepare_whitelist_params_as_query(self, whitelist_params, operator='='):
        """
        Get whitelist params as query params.
        :param whitelist_params {dict}
        :param operator {str} '=' or '!=' ...
        :return: {list} of query strings
        """
        queries = []
        for key, value in whitelist_params.items():
            if key:
                queries.append('{}{}{}'.format(key, operator, value))

        return queries

    def get_incidents(self, last_run, table_name):
        """
        Get tickets since last success time.
        :param last_run: {datetime} last run timestamp
        :param table_name: {str} table name
        :return: {list} of incidents {dict}

        """
        sn_last_time_format = self.sn_manager.convert_datetime_to_sn_format(last_run)
        incidents = []

        try:
            # Get tickets since last success time from specific table
            incidents = self.sn_manager.get_incidents_by_filter(creation_time=sn_last_time_format,
                                                                table_name=table_name,
                                                                custom_queries=self.get_whitelist_queries())
            # Sort tickets so the first will be the oldest ticket that was updated
            incidents = sorted(incidents, key=lambda incident: incident.sys_created_on)

            # Tickets limit per cycle - Default - The 10 oldest incidents (Ticket are sorted by times)
            incidents = incidents[:self.max_incidents_per_cycle]

            for incident in incidents:
                for key, value in incident.raw_data.items():
                    if isinstance(value, dict) and LINK_KEY in value:
                        try:
                            incident.raw_data[key]["context"] = self.sn_manager.get_additional_context_for_field(
                                link=value.get(LINK_KEY))
                        except Exception as e:
                            self.logger.error(f"Failed to fetch more context for incident {incident.number} "
                                              f"field \"{key}\". Error: {e}.")

        except Exception as e:
            if NO_RESULTS not in str(e):
                self.logger.error("Failed to fetch incidents")
                self.logger.exception(e)

        self.logger.info("Found {0} incidents since {1}.".format(len(incidents), str(sn_last_time_format)))

        return incidents

    def update_incident_user_info(self, incident):
        """
        Update incident user info
        :param incident: {Incident} Incident instance
        """
        if incident.opener_id and incident.caller_id:
            user_info = self.sn_manager.get_user_info(incident.opener_id, incident.caller_id)
            user_info = user_info[0] if user_info else None
            if user_info:
                incident.update_incident_with_user_info(user_info)

    def is_valid_incident_time(self, last_run_time, incident_dict):
        """
        Compare incident time to connector last run time to make sure incidents are not taken more than once.
        Base on the ServiceNow Api, incident fetch without time zone
        :param last_run_time: {datetime} last execution time from file
        :param incident_dict: {Incident object}
        :return: {Boolean}
        """
        # compare full dates
        incident_time = convert_string_to_datetime(incident_dict.get('opened_at'), timezone_str=self.server_time_zone)
        # Checking if incident is already taken, if yes - incident is not valid.
        if incident_time <= last_run_time:
            return False
        return True

    def create_event(self, incident, event_name):
        """
        Create events from incident data
        :param incident: {dict} All incident data
        :param event_name: {string} name of the event
        :return: event {dict} one event from the incident data
        """
        event_details = dict_to_flat(incident)
        event_details['event_name'] = event_name
        try:
            # Incident date is in UTC time, save time in unix (milliseconds).
            event_time = convert_datetime_to_unix_time(
                convert_string_to_datetime(incident.get('sys_created_on'),
                                           timezone_str=self.server_time_zone)) if incident.get(
                'sys_created_on') else 1
        except Exception as e:
            self.logger.error("Failed to get incident creation time. {0}".format(e))
            event_time = 1

        event_details['StartTime'] = event_details['EndTime'] = event_time
        return event_details

    @staticmethod
    def map_priority(sn_priority):
        """
        Mapping ServiceNow priority to siemplify priority
        :param sn_priority: {string} '1, 2 or 3' (1=high, 2=medium, 3=low)
        :return: {int} (40=low, 60=medium, 80=high)
        """
        return PRIORITY_MAPPING.get(sn_priority, LOW_PRIORITY)

    def create_case_info(self, incident, event, connector_environment, rule_generator_field):
        """
        Get alerts from Incident
        :param incident: {dict} An incident data
        :param event: {dict} one event from the incident data
        :param connector_environment: {string} Connector default environment
        :param rule_generator_field: {string} Rule generator field name
        :return: {CaseInfo} case
        """
        # Validate incident number exists
        case_info = CaseInfo()
        try:
            incident_number = incident['number']
            case_info.name = incident['number']
        except Exception as e:
            incident_number = incident['sys_id']
            case_info.name = incident_number
            self.logger.error("Found incident, cannot get its number. Get its SysID{0}".format(str(e)))
            self.logger.exception(e)

        self.logger.info("Creating Case for incident {}".format(incident_number))
        # Create the CaseInfo
        try:
            if rule_generator_field:
                case_info.rule_generator = incident.get(rule_generator_field, CASE_RULE_GENERATOR)
            else:
                case_info.rule_generator = CASE_RULE_GENERATOR

            try:
                # Incident date is in UTC time, save time in unix (milliseconds).
                case_info.start_time = convert_datetime_to_unix_time(
                    convert_string_to_datetime(incident.get('sys_created_on'),
                                               timezone_str=self.server_time_zone)) if incident.get(
                    'sys_created_on') else 1
            except Exception as e:
                self.logger.error("Failed to get incident creation time. {0}".format(e))
                case_info.start_time = 1

            case_info.end_time = case_info.start_time

            case_info.identifier = incident_number
            case_info.ticket_id = case_info.identifier
            # Priority mapped from service now values to siemplify values
            case_info.priority = self.map_priority(incident.get('urgency'))
            case_info.device_vendor = VENDOR
            case_info.device_product = PRODUCT_NAME
            case_info.display_id = case_info.identifier

            # Domain is set by the caller. Siemplify Environment = SN Domain
            try:
                domain_id = incident['sys_domain']['value']
                if domain_id != SN_DEFAULT_DOMAIN:
                    case_info.environment = self.sn_manager.get_full_domain_name_by_id(domain_id)
                else:
                    case_info.environment = connector_environment
            except Exception as e:
                self.logger.error("Failed to get incident domain.")
                self.logger.exception("Error: {0}".format(e))
                case_info.environment = connector_environment

            case_info.events = [event]

        except KeyError as e:
            raise KeyError("Mandatory key is missing: {}. Skipping Incident.".format(str(e)))

        return case_info


@output_handler
def main(is_test=False):
    connector_scope = SiemplifyConnectorExecution()
    output_variables = {}
    log_items = []

    connector_scope.LOGGER.info("======= Starting ServiceNow Connector. =======")

    try:

        default_incident_table = extract_connector_param(
            connector_scope,
            param_name="Incident Table",
            print_value=True,
            default_value=DEFAULT_TABLE
        )

        # Configurations.
        api_root = extract_connector_param(connector_scope, param_name="Api Root",
                                           print_value=True)
        username = extract_connector_param(connector_scope, param_name="Username",
                                           print_value=False)
        password = extract_connector_param(connector_scope, param_name="Password",
                                           print_value=False)
        verify_ssl = extract_connector_param(connector_scope, param_name="Verify SSL", default_value=True,
                                             input_type=bool)
        client_id = extract_connector_param(connector_scope, param_name="Client ID",
                                            print_value=False)
        client_secret = extract_connector_param(connector_scope, param_name="Client Secret",
                                                print_value=False)
        refresh_token = extract_connector_param(connector_scope, param_name="Refresh Token",
                                                print_value=False)
        use_oauth = extract_connector_param(connector_scope, param_name="Use Oauth Authentication",
                                            default_value=False, input_type=bool)

        service_now_manager = ServiceNowManager(api_root=api_root, username=username, password=password,
                                                default_incident_table=default_incident_table, verify_ssl=verify_ssl,
                                                siemplify_logger=connector_scope.LOGGER, client_id=client_id,
                                                client_secret=client_secret, refresh_token=refresh_token,
                                                use_oauth=use_oauth)

        days_backwards = extract_connector_param(connector_scope, param_name="Days Backwards", print_value=True,
                                                 input_type=int, default_value=DEFAULT_DAYS_BACKWARDS)
        max_incidents_per_cycle = extract_connector_param(connector_scope, param_name="Max Incidents Per Cycle",
                                                          print_value=True, input_type=int,
                                                          default_value=MAX_INCIDENTS_PER_CYCLE)
        server_time_zone = extract_connector_param(connector_scope, param_name="Server Time Zone", print_value=True,
                                                   default_value='UTC')
        rule_generator_field = extract_connector_param(connector_scope, param_name="Rule Generator", print_value=True)
        table_name = extract_connector_param(connector_scope, param_name="Table Name", print_value=True)
        event_name = extract_connector_param(connector_scope, param_name="Event Name", print_value=True,
                                             default_value=DEFAULT_EVENT_NAME)
        get_user_info = extract_connector_param(connector_scope, param_name="Get User Information", input_type=bool,
                                                print_value=True)
        whitelist_as_blacklist = extract_connector_param(connector_scope, param_name="Use whitelist as a blacklist",
                                                         input_type=bool, print_value=True)
        environments_whitelist = extract_connector_param(connector_scope, param_name="Environments Whitelist",
                                                         print_value=True)
        if environments_whitelist:
            environments_whitelist = environments_whitelist.split(",")
        else:
            environments_whitelist = []

        connector_environment = connector_scope.context.connector_info.environment

        servicenow_connector = ServiceNowConnector(connector_scope, CONNECTOR_NAME, service_now_manager,
                                                   max_incidents_per_cycle, server_time_zone, connector_scope.whitelist,
                                                   whitelist_as_blacklist)

        # Fix first time run
        last_run_time = siemplify_fetch_timestamp(connector_scope, datetime_format=True)
        last_calculated_run_time = validate_timestamp(last_run_time, days_backwards, offset_is_in_days=True)
        # Convert timezone
        aware_time = arrow.get(last_calculated_run_time).to(server_time_zone).datetime
        connector_scope.LOGGER.info(
            "Calculating connector last run time. Last run time is: {0}".format(last_calculated_run_time))

        # Get alerts
        connector_scope.LOGGER.info("Collecting Incidents.")
        incidents = servicenow_connector.get_incidents(aware_time, table_name)

        # Test on one incident only
        if is_test:
            incidents = incidents[:1]

        all_cases = []
        cases_to_ingest = []
        for incident in incidents:
            try:
                if get_user_info:
                    servicenow_connector.update_incident_user_info(incident)

                # Create security event
                event = servicenow_connector.create_event(incident.to_json(), event_name)

                # Create case info
                case = servicenow_connector.create_case_info(incident.to_json(), event, connector_environment,
                                                             rule_generator_field)

                is_overflow = is_overflowed(connector_scope, case, is_test)
                if is_overflow:
                    # Skipping this alert (and dot ingest it to siemplify)
                    connector_scope.LOGGER.info(
                        "{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping"
                            .format(alert_name=str(case.rule_generator),
                                    alert_identifier=str(case.ticket_id),
                                    environment=case.environment,
                                    product=str(case.device_product)))

                else:
                    # Validate that the environment is in the whitelist
                    if case.environment and (case.environment not in environments_whitelist) and environments_whitelist:
                        connector_scope.LOGGER.warn(
                            "Environment is not in whitelist - {}".format(str(case.environment)))
                    else:
                        # Ingest the case to siemplify
                        cases_to_ingest.append(case)
                all_cases.append(case)

            except Exception as e:
                connector_scope.LOGGER.error("Failed to create CaseInfo")
                connector_scope.LOGGER.error("Error Message: {}".format(str(e)))
                connector_scope.LOGGER.exception(e)
                if is_test:
                    raise

        connector_scope.LOGGER.info("Completed processing incidents.")
        connector_scope.LOGGER.info("Ingest case to Siemplify only if the domain incident is in the whitelist "
                                    "or if the Incident is in the Default domain.")

        # Get last successful execution time.
        if all_cases:
            # Sort the not_overflow_cases by the end time of each case.
            all_cases = sorted(all_cases, key=lambda case: case.end_time)
            # Last execution time is set to the newest message time
            new_last_run_time = all_cases[-1].end_time
        else:
            # last_calculated_run_time is datetime object. Convert it to milliseconds timestamp.
            new_last_run_time = convert_datetime_to_unix_time(aware_time)

        connector_scope.LOGGER.info("Create {} cases.".format(len(cases_to_ingest)))
        if is_test:
            connector_scope.LOGGER.info("======= ServiceNow Connector Test Finish. =======")
        else:
            siemplify_save_timestamp(connector_scope, new_timestamp=new_last_run_time)

            connector_scope.LOGGER.info("======= ServiceNow Connector Finish. =======")

        connector_scope.return_package(cases_to_ingest, output_variables, log_items)

    except Exception as e:
        if not is_test:
            connector_scope.LOGGER.error(str(e))
            connector_scope.LOGGER.exception(e)
        else:
            connector_scope.LOGGER.exception(e)
            raise


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == 'True':
        print("Main execution started")
        main()
    else:
        print("Test execution started")
        main(is_test=True)
