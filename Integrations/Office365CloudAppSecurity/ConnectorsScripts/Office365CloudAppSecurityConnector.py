import datetime
import sys

from Office365CloudAppSecurityManager import Office365CloudAppSecurityManager, Office365CloudAppSecurityRateLimitingError
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import utc_now, output_handler, convert_datetime_to_unix_time
from utils import is_first_run, get_alert_info_events
from EnvironmentCommon import GetEnvironmentCommonFactory
from TIPCommon import (
    extract_connector_param,
    read_ids,
    write_ids,
    get_last_success_time,
    is_approaching_timeout,
    is_overflowed, dict_to_flat
)

connector_starting_time_datetime = utc_now()
connector_starting_time_ms = convert_datetime_to_unix_time(connector_starting_time_datetime)

# CONSTANTS
CONNECTOR_NAME = "Office 365 CloudApp Security Connector"
DEFAULT_OFFSET_TIME_HOURS = 24
DEFAULT_ALERTS_LIMIT = 100
DEFAULT_ALERTS_PADDING_PERIOD = 0
STORED_IDS_LIMIT = 3000


@output_handler
def main(is_test_run):
    alerts = []
    all_alerts = []
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = CONNECTOR_NAME

    if (is_test_run):
        siemplify.LOGGER.info("***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******")

    try:
        siemplify.LOGGER.info("==================== Main - Param Init ====================")

        api_root = extract_connector_param(siemplify, param_name="Cloud App Security portal URL", is_mandatory=True, print_value=True)
        api_key = extract_connector_param(siemplify, param_name="API Token", is_mandatory=True, print_value=False)
        verify_ssl = extract_connector_param(siemplify, param_name="Verify SSL", is_mandatory=False, print_value=True,
                                             input_type=bool, default_value=False)
        first_time_run_offset_in_hours = extract_connector_param(siemplify, param_name='Offset Time In Hours', is_mandatory=True,
                                                                 input_type=int, default_value=DEFAULT_OFFSET_TIME_HOURS, print_value=True)
        alerts_padding_period = extract_connector_param(siemplify, param_name='Alerts Padding Period', is_mandatory=False,
                                                        input_type=int, default_value=DEFAULT_ALERTS_PADDING_PERIOD, print_value=True)
        python_process_timeout = extract_connector_param(siemplify, param_name="PythonProcessTimeout", input_type=int,
                                                         is_mandatory=True, print_value=True)
        environment_field_name = extract_connector_param(siemplify, param_name='Environment Field Name', default_value='',
                                                         is_mandatory=False, print_value=True)
        environment_regex = extract_connector_param(siemplify, param_name='Environment Regex Pattern', is_mandatory=False, print_value=True)
        alerts_limit = extract_connector_param(siemplify, param_name='Max Alerts Per Cycle', input_type=int, is_mandatory=True,
                                               default_value=DEFAULT_ALERTS_LIMIT)

        siemplify.LOGGER.info("------------------- Main - Started -------------------")

        if python_process_timeout < 0:
            raise Exception("\"Script Timeout (Seconds)\" parameter cannot be negative.")

        if alerts_limit < 0:
            raise Exception("\"Max Alerts Per Cycle\" parameter cannot be negative.")

        if alerts_padding_period < 0:
            raise Exception("\"Alerts Padding Period\" parameter cannot be negative.")

        environment_common = GetEnvironmentCommonFactory.create_environment_manager(
            siemplify, environment_field_name, environment_regex)

        last_success_time_datetime = get_last_success_time(
            siemplify=siemplify,
            offset_with_metric={'hours': first_time_run_offset_in_hours}
        )

        cloud_app_manager = Office365CloudAppSecurityManager(
            api_root=api_root,
            api_token=api_key,
            verify_ssl=verify_ssl,
            siemplify=siemplify
        )

        # Read already existing alerts ids
        siemplify.LOGGER.info('Reading already existing alerts ids...')
        existing_ids = read_ids(siemplify)

        # Adjust alerts padding only if provided and not connector's first run
        if alerts_padding_period and not is_first_run(siemplify=siemplify, offset_hours=first_time_run_offset_in_hours,
                                                      connector_start_time=connector_starting_time_datetime):
            last_success_time_datetime = last_success_time_datetime - datetime.timedelta(minutes=alerts_padding_period)
            siemplify.LOGGER.info(f"Alerts fetching padding adjusted {alerts_padding_period} minutes backwards from last success time")

        try:
            siemplify.LOGGER.info(f"Fetching alerts")
            filtered_alerts = cloud_app_manager.get_alerts(
                start_time=convert_datetime_to_unix_time(last_success_time_datetime),
                limit=alerts_limit,
                existing_ids=existing_ids
            )
        except Office365CloudAppSecurityRateLimitingError as error:
            raise Office365CloudAppSecurityRateLimitingError(
                "{} Please consider decreasing \"Alerts Padding Period\", \"Max Alerts To Fetch\" parameters or increasing Connector Execution Interval".format(
                    error)
            )

        filtered_alerts = sorted(filtered_alerts, key=lambda alert: alert.start_time)
        siemplify.LOGGER.info(
            "Found {} new alerts in since {}.".format(
                len(filtered_alerts), last_success_time_datetime.isoformat())
        )

        if is_test_run:
            siemplify.LOGGER.info("This is a TEST run. Only 1 alert will be processed.")
            filtered_alerts = filtered_alerts[:1]

        # In this template example, we create a random number of dummy alerts:
        for alert in filtered_alerts:
            try:
                if is_approaching_timeout(connector_starting_time_ms, python_process_timeout):
                    siemplify.LOGGER.info('Timeout is approaching. Connector will gracefully exit')
                    break

                siemplify.LOGGER.info("Processing alert {}".format(alert.alert_id))
                siemplify.LOGGER.info("Fetching activities of alert {}".format(alert.alert_id))

                try:
                    activities = cloud_app_manager.get_alert_activities(alert.alert_id)
                    siemplify.LOGGER.info("Found {} activities".format(len(activities)))
                except Office365CloudAppSecurityRateLimitingError as error:
                    siemplify.LOGGER.error(
                        "{} Please consider decreasing \"Alerts Padding Period\", \"Max Alerts To Fetch\" parameters or "
                        "increasing Connector Execution Interval".format(error)
                    )
                    siemplify.LOGGER.exception(error)
                    break

                except Exception as e:
                    siemplify.LOGGER.error(
                        "Failed fetching activities of alert {}. Alert will be processed with no events.".format(
                            alert.alert_id)
                    )
                    siemplify.LOGGER.exception(e)
                    activities = []

                existing_ids.append(alert.alert_id)
                all_alerts.append(alert)
                alert_info = create_alert_info(siemplify, environment_common, alert, activities)

                if is_overflowed(siemplify,alert_info,is_test_run):
                    siemplify.LOGGER.info(
                        "{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping."
                            .format(alert_name=str(alert_info.rule_generator),
                                    alert_identifier=str(alert_info.ticket_id),
                                    environment=str(alert_info.environment),
                                    product=str(alert_info.device_product)))

                else:
                    alerts.append(alert_info)

                    siemplify.LOGGER.info('Alert {} was created.'.format(alert.alert_id))

                    if len(alerts) >= alerts_limit:
                        # Provide slicing for the alarms amount.
                        siemplify.LOGGER.info(
                            'Reached max number of alerts cycle. No more alerts will be processed in this cycle.'
                        )
                        break

            except Exception as e:
                siemplify.LOGGER.error("Failed to process alert {}".format(alert.alert_id), alert_id=alert.alert_id)
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

        if not is_test_run:
            if all_alerts:
                new_timestamp = all_alerts[-1].start_time + 1
                if new_timestamp > convert_datetime_to_unix_time(last_success_time_datetime):
                    # The timestamps are in milliseconds but the search in Cloud App is Greater or Equal
                    # So increase the last found timestamp by 1 millisecond to proceed to the next millisecond
                    siemplify.save_timestamp(new_timestamp=new_timestamp)
                    siemplify.LOGGER.info('New timestamp {} has been saved'.format(new_timestamp))
            write_ids(siemplify, existing_ids,stored_ids_limit=STORED_IDS_LIMIT)

    except Exception as err:
        siemplify.LOGGER.error('Got exception on main handler. Error: {0}'.format(err))
        siemplify.LOGGER.exception(err)
        if is_test_run:
            raise

    siemplify.LOGGER.info("Created total of {} cases".format(len(alerts)))
    siemplify.LOGGER.info("------------------- Main - Finished -------------------")
    siemplify.return_package(alerts)



def create_alert_info(siemplify, environment_common, alert, activities):
    """
    Creat an AlertInfo object from a single alert and its activities
    :param siemplify: {SiemplifyConnectorExecution} The connector obj
    :param environment_common: {EnvironmentHandle} The environment handle instance
    :param alert: {Alert} An alert instance
    :param activities: [Activity] A list of the activity objects related to the alert
    :return: {AlertInfo} The created alert info object
    """
    siemplify.LOGGER.info("-------------- Started processing Alert {}".format(alert.alert_id), alert_id=alert.alert_id)

    alert_info = AlertInfo()
    alert_info.display_id = alert.alert_id
    alert_info.ticket_id = alert.alert_id
    alert_info.name = alert.alert_name
    alert_info.rule_generator = alert.rule_generator
    alert_info.start_time = alert.start_time
    alert_info.end_time = alert.end_time
    alert_info.priority = alert.alert_severity
    alert_info.description = alert.description
    alert_info.device_vendor = alert.vendor_name
    alert_info.device_product = alert.product_name
    alert_info.events = get_alert_info_events(alert, activities)
    alert_info.extensions = alert.as_extension()
    environment = environment_common.get_environment(dict_to_flat(alert.raw_data))

    if environment:
        alert_info.environment = environment
    else:
        alert_info.environment = siemplify.context.connector_info.environment

    siemplify.LOGGER.info("-------------- Finished processing Alert {}".format(alert.alert_id), alert_id=alert.alert_id)
    return alert_info



if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test_run)
