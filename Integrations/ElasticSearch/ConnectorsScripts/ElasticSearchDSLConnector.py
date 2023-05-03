import datetime
import json
import sys
from ElasticsearchManager import ElasticsearchManager
from EnvironmentCommon import GetEnvironmentCommonFactory
from SiemplifyConnectors import CaseInfo, SiemplifyConnectorExecution
from SiemplifyUtils import output_handler
from SiemplifyUtils import utc_now, convert_string_to_unix_time
from TIPCommon import extract_connector_param, dict_to_flat, get_last_success_time, is_overflowed, save_timestamp
from UtilsManager import load_custom_severity_configuration, map_severity_value, get_field_value, DEFAULT_SEVERITY_VALUE

# ============================== CONSTS ===================================== #
DEFAULT_VENDOR = "ElasticSearch"
SCRIPT_NAME = "ElasticSerach DSL Connector"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
ALERTS_LIMIT = 20
DEFAULT_DAYS_BACKWARDS = 3
TIMEZONE = "UTC"
NON_SOURCE_FIELDS = ["_id", "_index", "_score", "_type"]

ALERT_LOW_SEVERITY = "LOW"
SEVERITY_MAP = {
    "INFO": -1,
    "LOW": 40,
    "MEDIUM": 60,
    "HIGH": 80,
    "CRITICAL": 100
}

# ============================= CLASSES ===================================== #


class ElasticSearchDSLConnectorException(Exception):
    """
    ElasticSearch Exception
    """
    pass


class ElasticSearchDSLConnector(object):
    """
    ElasticSearch Connector
    """

    def __init__(self, connector_scope, elastic_manager, device_product_field_name, event_class_id_field_name,
                 alert_name_field, timestamp_field_name,
                 alert_description_field, alert_severity, environment_common, environment_field_name):
        self.connector_scope = connector_scope
        self.logger = connector_scope.LOGGER
        self.elastic_manager = elastic_manager
        self.device_product_field_name = device_product_field_name
        self.event_class_id_field_name = event_class_id_field_name
        self.alert_name_field = alert_name_field
        self.timestamp_field_name = timestamp_field_name
        self.alert_description_field = alert_description_field
        self.alert_severity = alert_severity
        self.environment_common = environment_common
        self.environment_field_name = environment_field_name

    @staticmethod
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

    def get_alerts(self, last_run, indexes=None, query=None,
                   alerts_count_limit=ALERTS_LIMIT):
        """
        Fetch alerts from ElasticSearch
        :return: {list} List of found alerts
        """
        self.logger.info("Querying DSL since {}".format(last_run))
        all_alerts, total_hits = self.elastic_manager.dsl_search( indexes, query, alerts_count_limit)

        return sorted(
            all_alerts,
            key=lambda alert: get_field_value(dict_to_flat(alert), self.timestamp_field_name, "0")
        )

    def create_case_info(self, flat_alert, indexes, query, environment_regex_pattern, severity_field_name):
        """
        Create CaseInfo object from ElasticSearch alert
        :param flat_alert: {dict} An ES flattened alert
        :param indexes: {str} The indexes to search by
        :param query: {str} The search query to search by
        :param environment_regex_pattern: {str} The regex pattern to extract environment from the environment field
        :param severity_field_name: {str} Name of severity field
        :return: {CaseInfo} The newly created case
        """
        self.logger.info(
            "Creating Case for Alert {}".format(flat_alert['_id']))

        try:
            # Create the CaseInfo
            case_info = CaseInfo()

            name = get_field_value(flat_alert, self.alert_name_field, "")
            case_info.name = name
            case_info.ticket_id = flat_alert['_id']

            case_info.rule_generator = name
            case_info.display_id = flat_alert['_id']
            case_info.device_vendor = DEFAULT_VENDOR

            case_info.device_product = get_field_value(flat_alert, self.device_product_field_name, "")
            flat_alert[self.event_class_id_field_name] = get_field_value(flat_alert, self.event_class_id_field_name, "")

            try:
                alert_time = convert_string_to_unix_time(get_field_value(flat_alert, self.timestamp_field_name))
            except Exception as e:
                self.logger.error(
                    "Unable to get alert time: {}".format(e))
                self.logger.exception(e)
                alert_time = 1

            case_info.start_time = alert_time
            case_info.end_time = alert_time

            flat_alert[self.environment_field_name] = get_field_value(flat_alert, self.environment_field_name, "")
            case_info.environment = self.environment_common.get_environment(flat_alert)

        except KeyError as e:
            raise KeyError("Mandatory key is missing: {}".format(e))

        case_info.events = [flat_alert]
        case_info.extensions.update({
            'ES Index': indexes,
            'ES Query': query
        })
        case_info.description = get_field_value(flat_alert, self.alert_description_field, "")
        if self.alert_severity:
            case_info.priority = self.alert_severity
        else:
            case_info.priority = map_severity_value(severity_field_name, get_field_value(flat_alert, severity_field_name,
                                                                                         DEFAULT_SEVERITY_VALUE))
        return case_info


@output_handler
def main(test=False):
    """
    Main execution - ElasticSearch Connector
    """
    connector_scope = SiemplifyConnectorExecution()
    connector_scope.script_name = SCRIPT_NAME
    output_variables = {}
    log_items = []

    if test:
        connector_scope.LOGGER.info("Starting Connector Test.")
        connector_scope.LOGGER.info("Testing connection to ElasticSearch")

    else:
        connector_scope.LOGGER.info("Starting Connector.")
        connector_scope.LOGGER.info("Connecting to ElasticSearch")

    try:
        server_address = extract_connector_param(connector_scope, param_name="Server Address", input_type=str)
        username = extract_connector_param(connector_scope, param_name="Username", input_type=str)
        password = extract_connector_param(connector_scope, param_name="Password", input_type=str)

        authenticate = extract_connector_param(connector_scope, param_name="Authenticate", input_type=bool)
        verify_ssl = extract_connector_param(connector_scope, param_name="Verify SSL", input_type=bool)
        ca_certificate_file = extract_connector_param(connector_scope, param_name="CA Certificate File", input_type=str)

        device_product_field_name = extract_connector_param(connector_scope, param_name="DeviceProductField", input_type=str)
        event_class_id_field_name = extract_connector_param(connector_scope, param_name="EventClassId",
                                                            input_type=str)
        alert_name_field = extract_connector_param(connector_scope, param_name="Alert Field Name", input_type=str)
        alert_description_field = extract_connector_param(connector_scope, param_name="Alert Description Field", input_type=str)
        alert_severity = extract_connector_param(connector_scope, param_name="Alert Severity", input_type=str)

        if alert_severity:
            if alert_severity.upper() in SEVERITY_MAP:
                alert_severity = SEVERITY_MAP[alert_severity.upper()]
            else:
                raise ElasticSearchDSLConnectorException("Alert Severity isn't valid value")

        timestamp_field_name = extract_connector_param(connector_scope, param_name="Timestamp Field", input_type=str)
        environment_field_name = extract_connector_param(connector_scope, param_name="Environment Field Name", input_type=str)
        environment_regex_pattern = extract_connector_param(connector_scope, param_name="Environment Regex Pattern", input_type=str)
        index = extract_connector_param(connector_scope, param_name="Index", input_type=str)
        query = extract_connector_param(connector_scope, param_name="Query", input_type=str)

        try:
            json.loads(query)
        except:
            raise ElasticSearchDSLConnectorException("Provide valid json for query")

        alerts_count_limit = extract_connector_param(connector_scope, param_name="Alerts Count Limit", input_type=str)
        max_days_backwards = extract_connector_param(connector_scope, param_name="Max Days Backwards",
                                                                default_value=DEFAULT_DAYS_BACKWARDS, input_type=int)
        # Connect to ElasticSearch
        if authenticate:
            elastic_manager = ElasticsearchManager(server_address, username, password, verify_ssl=verify_ssl,
                                                   ca_certificate_file=ca_certificate_file)
        else:
            elastic_manager = ElasticsearchManager(server_address,
                                                   verify_ssl=verify_ssl, ca_certificate_file=ca_certificate_file)

        environment_common = GetEnvironmentCommonFactory.create_environment_manager(
            connector_scope,
            environment_field_name,
            environment_regex_pattern
        )

        elastic_connector = ElasticSearchDSLConnector(connector_scope,
                                                      elastic_manager,
                                                      device_product_field_name,
                                                      event_class_id_field_name,
                                                      alert_name_field,
                                                      timestamp_field_name,
                                                      alert_description_field,
                                                      alert_severity,
                                                      environment_common,
                                                      environment_field_name)

        severity_field_name = extract_connector_param(connector_scope, param_name="Severity Field Name",
                                                      input_type=str)

        load_custom_severity_configuration(connector_scope, severity_field_name)

        # Get alerts from ElasticSearch
        if test:
            connector_scope.LOGGER.info("Trying to fetch alerts.")
        else:
            connector_scope.LOGGER.info("Collecting alerts from ElasticSearch.")

        last_calculated_run_time = get_last_success_time(
            connector_scope,
            offset_with_metric={'days': max_days_backwards}
        )

        alerts = elastic_connector.get_alerts(last_calculated_run_time.strftime(TIME_FORMAT), index, query, alerts_count_limit)

        if test:
            alerts = alerts[:1]

        # Construct CaseInfo from alerts
        cases = []
        all_cases = []

        for alert in alerts:
            try:
                flat_alert = dict_to_flat(alert)
                try:
                    alert_name = get_field_value(flat_alert, alert_name_field)
                except Exception as e:
                    connector_scope.LOGGER.error("Unable to get rule name: {}".format(e))
                    connector_scope.LOGGER.exception(e)
                    alert_name = ""

                connector_scope.LOGGER.info("Processing alert {}: ".format(alert['_id'],
                                                                           alert_name))

                case = elastic_connector.create_case_info(flat_alert, index, query, environment_regex_pattern, severity_field_name)
                all_cases.append(case)

                if is_overflowed(connector_scope, case, test):
                    connector_scope.LOGGER.info(
                        '{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping.'
                            .format(alert_name=str(case.rule_generator),
                                    alert_identifier=str(case.ticket_id),
                                    environment=str(case.environment),
                                    product=str(case.device_product)))
                    # If is overflowed we should skip
                    continue

                cases.append(case)
            except Exception as e:
                # Failed to build CaseInfo for alert
                connector_scope.LOGGER.error("Failed to create CaseInfo for alert {}: {}".format(alert['_id'], e))
                connector_scope.LOGGER.error("Error Message: {}".format(e))
                if test:
                    raise

        connector_scope.LOGGER.info("Found total {} cases, non-overflowed cases: {}".format(len(all_cases), len(cases)))

        if test:
            if len(all_cases) != len(alerts):
                connector_scope.LOGGER.error("Failed to create cases for some alerts. Check logs for details.")

            else:
                connector_scope.LOGGER.info("Successfully constructed CaseInfo for all alerts.")

            connector_scope.LOGGER.info("Test completed.")
            connector_scope.return_package(cases, output_variables, log_items)
            return

        # Set the new timestamp
        if cases:
            try:
                # Save last index's timestamp
                save_timestamp(siemplify=connector_scope, alerts=all_cases, timestamp_key='end_time')
            except Exception as e:
                connector_scope.LOGGER.error("Unable to write timestamp: {}".format(e))
                connector_scope.LOGGER.exception(e)

        # Return data
        connector_scope.LOGGER.info("Completed. Total {} cases created.".format(len(cases)))
        connector_scope.return_package(cases, output_variables, log_items)

    except Exception as e:
        connector_scope.LOGGER.error(e)
        connector_scope.LOGGER.exception(e)
        if test:
            raise


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == 'True':
        print("Main execution started")
        main(test=False)
    else:
        print("Test execution started")
        main(test=True)
