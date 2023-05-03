import sys
from ElasticsearchManager import ElasticsearchManager
from EnvironmentCommon import GetEnvironmentCommonFactory
from SiemplifyConnectors import CaseInfo, SiemplifyConnectorExecution
from SiemplifyUtils import output_handler
from SiemplifyUtils import unix_now, convert_string_to_unix_time, convert_unixtime_to_datetime
from TIPCommon import dict_to_flat, read_ids_by_timestamp, write_ids_with_timestamp, save_timestamp, \
    get_last_success_time, is_overflowed
from UtilsManager import load_custom_severity_configuration, map_severity_value, get_field_value, DEFAULT_SEVERITY_VALUE

# ============================== CONSTS ===================================== #
DEFAULT_VENDOR = "ElasticSearch"
SCRIPT_NAME = "ElasticSerach Connector"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
ALERTS_LIMIT = 20
DEFAULT_DAYS_BACKWARDS = 3
TIMEZONE = "UTC"
NON_SOURCE_FIELDS = ["_id", "_index", "_score", "_type"]


# ============================= CLASSES ===================================== #


class ElasticSearchConnectorException(Exception):
    """
    ElasticSearch Exception
    """
    pass


class ElasticSearchConnector(object):
    """
    ElasticSearch Connector
    """

    def __init__(self, connector_scope, elastic_manager, device_product_field_name,
                 alert_name_field, timestamp_field_name, environment_common, environment_field_name):
        self.connector_scope = connector_scope
        self.logger = connector_scope.LOGGER
        self.elastic_manager = elastic_manager
        self.device_product_field_name = device_product_field_name
        self.alert_name_field = alert_name_field
        self.environment_common = environment_common
        self.environment_field_name = environment_field_name
        self.timestamp_field_name = timestamp_field_name

    def get_alerts(self, last_run, indexes=None, query=None, existing_ids=[], limit=None):
        """
        Fetch alerts from ElasticSearch
        :return: {list} List of found alerts
        """
        self.logger.info("Querying ES since {}".format(last_run))
        all_alerts, _, _ = self.elastic_manager.advanced_es_search(
            **{
                'Index': indexes,
                'Query': query,
                'Oldest Date': last_run,
                'Timestamp Field': self.timestamp_field_name,
                'Existing IDs': existing_ids,
                'Limit': limit

            }
        )

        return sorted(
            all_alerts,
            key=lambda alert: get_field_value(dict_to_flat(alert), self.timestamp_field_name, 0)
        )

    def create_case_info(self, flat_alert, indexes, query, event_field_name, severity_field_name):
        """
        Create CaseInfo object from ElasticSearch alert
        :param flat_alert: {dict} An ES flattened alert
        :param indexes: {str} The indexes to search by
        :param query: {str} The search query to search by
        :param event_field_name: {str} The EventClassId
        :param severity_field_name: {str} Name of severity field
        :return: {CaseInfo} The newly created case
        """
        self.logger.info(
            "Creating Case for Alert {}".format(str(flat_alert['_id']).encode("utf-8")))

        try:
            # Create the CaseInfo
            case_info = CaseInfo()

            try:
                name = get_field_value(flat_alert, self.alert_name_field)
            except Exception as e:
                self.logger.error("Unable to get alert name: {}".format(str(e)))
                self.logger.exception(e)
                name = ""

            case_info.name = name
            case_info.ticket_id = flat_alert['_id']

            case_info.rule_generator = name
            case_info.display_id = flat_alert['_id']
            case_info.device_vendor = DEFAULT_VENDOR

            try:
                device_product = get_field_value(flat_alert, self.device_product_field_name)
            except Exception as e:
                self.logger.error("Unable to get device_product: {}".format(str(e)))
                self.logger.exception(e)
                device_product = ""

            case_info.device_product = device_product

            timestamp_value = get_field_value(flat_alert, self.timestamp_field_name)
            
            try:
                alert_time = convert_string_to_unix_time(timestamp_value)
            except Exception as e:
                
                try:
                    timestamp_value = "{}Z".format(timestamp_value)
                    alert_time = convert_string_to_unix_time(timestamp_value)
                    
                except Exception as e:
                    self.logger.error(
                        "Unable to get alert time: {}".format(str(e)))
                    self.logger.exception(e)
                    alert_time = 1

            case_info.start_time = alert_time
            case_info.end_time = alert_time

            flat_alert[self.environment_field_name] = get_field_value(
                flat_alert, self.environment_field_name, self.connector_scope.context.connector_info.environment
            )
            case_info.environment = self.environment_common.get_environment(flat_alert)

            case_info.priority = map_severity_value(severity_field_name,
                                                    get_field_value(flat_alert, severity_field_name,
                                                                    DEFAULT_SEVERITY_VALUE))

        except KeyError as e:
            raise KeyError("Mandatory key is missing: {}".format(str(e)))

        if event_field_name not in flat_alert:
            try:
                flat_alert[event_field_name] = get_field_value(flat_alert, event_field_name)
            except Exception as e:
                self.logger.error("Unable to get event_field_name: {}".format(str(e)))
                self.logger.exception(e)

        case_info.events = [flat_alert]
        case_info.extensions.update({
            'ES Index': indexes,
            'ES Query': query
        })
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
        server_address = connector_scope.parameters.get('Server Address')
        username = connector_scope.parameters.get('Username')
        password = connector_scope.parameters.get('Password')
        api_token = connector_scope.parameters.get('API Token')
        authenticate = connector_scope.parameters['Authenticate'].lower() == 'true'
        verify_ssl = connector_scope.parameters['Verify SSL'].lower() == 'true'
        ca_certificate_file = connector_scope.parameters.get('CA Certificate File')
        
        device_product_field_name = connector_scope.parameters.get('DeviceProductField')
        alert_name_field = connector_scope.parameters.get('Alert Name Field')
        timestamp_field_name = connector_scope.parameters.get('Timestamp Field')
        environment_field_name = connector_scope.parameters.get('Environment Field')
        environment_regex_pattern = connector_scope.parameters.get('Environment Regex Pattern')
        indexes = connector_scope.parameters.get('Indexes')
        query = connector_scope.parameters.get('Query')
        alerts_count_limit = int(
            connector_scope.parameters.get('Alerts Count Limit', 0)) if connector_scope.parameters.get(
            'Alerts Count Limit') else ALERTS_LIMIT
        max_days_backwards = int(
            connector_scope.parameters.get('Max Days Backwards')) if connector_scope.parameters.get(
            'Max Days Backwards') else DEFAULT_DAYS_BACKWARDS
        event_field_name = connector_scope.parameters.get('EventClassId')

        # Connect to ElasticSearch
        if authenticate:
            elastic_manager = ElasticsearchManager(server_address, username=username, password=password,
                                                   api_token=api_token, verify_ssl=verify_ssl,
                                                   ca_certificate_file=ca_certificate_file, authenticate=True)
        else:
            elastic_manager = ElasticsearchManager(server_address, ca_certificate_file=ca_certificate_file,
                                                   verify_ssl=verify_ssl)

        environment_common = GetEnvironmentCommonFactory.create_environment_manager(
            connector_scope,
            environment_field_name,
            environment_regex_pattern
        )

        elastic_connector = ElasticSearchConnector(connector_scope,
                                                   elastic_manager,
                                                   device_product_field_name,
                                                   alert_name_field,
                                                   timestamp_field_name,
                                                   environment_common,
                                                   environment_field_name)

        severity_field_name = connector_scope.parameters.get('Severity Field Name')

        load_custom_severity_configuration(connector_scope, severity_field_name)
        # Get existing ids
        existing_ids = read_ids_by_timestamp(connector_scope, offset_in_hours=6, convert_to_milliseconds=True)

        # Get alerts from ElasticSearch
        if test:
            connector_scope.LOGGER.info("Trying to fetch alerts.")
        else:
            connector_scope.LOGGER.info("Collecting alerts from ElasticSearch.")

        last_calculated_run_time = get_last_success_time(
            connector_scope,
            offset_with_metric={'days': max_days_backwards}
        )

        alerts = elastic_connector.get_alerts(last_calculated_run_time.strftime(TIME_FORMAT), indexes, query,
                                              list(existing_ids.keys()), alerts_count_limit)

        connector_scope.LOGGER.info(
            "Found {} new alerts since {}.".format(len(alerts), last_calculated_run_time.isoformat())
        )

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
                    connector_scope.LOGGER.error("Unable to get alert name: {}".format(str(e)))
                    connector_scope.LOGGER.exception(e)
                    alert_name = ""

                case = elastic_connector.create_case_info(flat_alert, indexes, query, event_field_name, severity_field_name)
                connector_scope.LOGGER.info(
                    "Alert timestamp: {}".format(convert_unixtime_to_datetime(case.start_time).isoformat()))
                existing_ids.update({alert['_id']: unix_now()})
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
                if alerts_count_limit and len(cases) >= alerts_count_limit:
                    connector_scope.LOGGER.info("Reached alerts limit per cycle.")
                    break

            except Exception as e:
                # Failed to build CaseInfo for alert
                connector_scope.LOGGER.error("Failed to create CaseInfo for alert {}: {}".format(alert['_id'], str(e)))
                connector_scope.LOGGER.error("Error Message: {}".format(str(e)))
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
                # Save last index's timestamp - 1 (elastic performs greater than searches and not greater or equal
                # so if we save the new timestamp as is, we might miss records)
                save_timestamp(siemplify=connector_scope, alerts=all_cases, timestamp_key='end_time',
                               incrementation_value=-1)
            except Exception as e:
                connector_scope.LOGGER.error("Unable to write timestamp: {}".format(str(e)))
                connector_scope.LOGGER.exception(e)

            write_ids_with_timestamp(connector_scope, existing_ids)
        # Return data
        connector_scope.LOGGER.info("Completed. Total {} cases created.".format(len(cases)))
        connector_scope.return_package(cases, output_variables, log_items)

    except Exception as e:
        connector_scope.LOGGER.error(str(e))
        connector_scope.LOGGER.exception(str(e))
        if test:
            raise


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == 'True':
        print("Main execution started")
        main(test=False)
    else:
        print("Test execution started")
        main(test=True)
