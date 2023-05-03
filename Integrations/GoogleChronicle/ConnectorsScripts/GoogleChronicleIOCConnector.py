import sys
import json
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyUtils import output_handler, unix_now
from GoogleChronicleManager import GoogleChronicleManager
from TIPCommon import extract_connector_param
import consts
import utils
import exceptions


# =====================================
#             CONSTANTS               #
# =====================================
CONNECTOR_NAME = 'Google Chronicle - IoCs Connector'
HOURS_LIMIT_IN_IDS_FILE = 72
TIMEOUT_THRESHOLD = 0.9


@output_handler
def main(is_test_run):
    connector_starting_time = unix_now()
    processed_alerts = []
    processed_iocs = []
    siemplify = SiemplifyConnectorExecution()  # Siemplify main SDK wrapper
    siemplify.script_name = CONNECTOR_NAME

    try:
        if is_test_run:
            siemplify.LOGGER.info('***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******')

        siemplify.LOGGER.info('------------------- Main - Param Init -------------------')

        creds = extract_connector_param(siemplify, param_name='Service Account Credentials', is_mandatory=True)

        try:
            creds = json.loads(creds)
        except Exception as e:
            siemplify.LOGGER.error("Unable to parse credentials as JSON.")
            siemplify.LOGGER.exception(e)
            raise exceptions.GoogleChronicleValidationError("Unable to parse credentials as JSON. Please validate creds.")

        environment_field_name = extract_connector_param(siemplify, param_name='Environment Field Name', default_value='',
                                                         print_value=True)
        environment_regex_pattern = extract_connector_param(siemplify, param_name='Environment Regex Pattern',
                                                            default_value='', print_value=True)

        hours_backwards = extract_connector_param(siemplify, param_name='Fetch Max Hours Backwards', input_type=int,
                                                  is_mandatory=False, default_value=1, print_value=True)

        python_process_timeout = extract_connector_param(siemplify, param_name="PythonProcessTimeout", input_type=int,
                                                         is_mandatory=True, print_value=True)

        siemplify.LOGGER.info('------------------- Main - Started -------------------')

        manager = GoogleChronicleManager(**creds)

        # Read already existing alerts ids
        siemplify.LOGGER.info("Loading existing ids from IDS file.")
        existing_ids = utils.read_ids(siemplify, max_hours_backwards=HOURS_LIMIT_IN_IDS_FILE)
        siemplify.LOGGER.info('Found {} existing ids in ids.json'.format(len(existing_ids)))

        last_success_time = utils.get_last_success_time(siemplify=siemplify,
                                                        offset_with_metric={'hours': hours_backwards})
        now = unix_now()
        siemplify.LOGGER.info("Fetching IOCs since {}".format(last_success_time.isoformat()))

        more_results_available, fetched_alerts = manager.list_iocs(
            start_time=utils.datetime_to_rfc3339(last_success_time),
            limit=consts.MAX_LIMIT
        )
        filtered_alerts = utils.filter_old_alerts(siemplify.LOGGER, fetched_alerts, existing_ids, id_key='hash_id')
        filtered_alerts = sorted(filtered_alerts, key=lambda filtered_alert: filtered_alert.last_seen_time_ms)

        siemplify.LOGGER.info(
            "Found {} new alert in since {}.".format(len(filtered_alerts), last_success_time.isoformat()))

        if is_test_run:
            siemplify.LOGGER.info('This is a TEST run. Only 1 alert will be processed.')
            filtered_alerts = filtered_alerts[:1]

        for alert in filtered_alerts:
            try:
                if utils.is_approaching_timeout(python_process_timeout, connector_starting_time, TIMEOUT_THRESHOLD):
                    siemplify.LOGGER.info('Timeout is approaching. Connector will gracefully exit.')
                    break

                siemplify.LOGGER.info('Started processing Alert {}'.format(alert.hash_id), alert_id=alert.hash_id)

                existing_ids.update({alert.hash_id: unix_now()})

                alert_info = alert.as_alert_info(
                    utils.get_environment_common(siemplify, environment_field_name, environment_regex_pattern)
                )

                siemplify.LOGGER.info("ID: {}, Domain Name: {}, Last Seen Time: {}, Severity: {}".format(
                    alert.hash_id, alert.domain_name, alert.last_seen_time, alert.siemplify_severity
                ))

                # Add alert to processed iocs (regardless of overflow status) to mark it as processed
                processed_iocs.append(alert)

                if utils.is_overflowed(siemplify, alert_info, is_test_run):
                    siemplify.LOGGER.info(
                        '{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping.'
                            .format(alert_name=alert_info.rule_generator,
                                    alert_identifier=alert_info.ticket_id,
                                    environment=alert_info.environment,
                                    product=alert_info.device_product))
                    # If is overflowed we should skip
                    continue

                processed_alerts.append(alert_info)
                siemplify.LOGGER.info('Alert {} was created.'.format(alert.hash_id))

            except Exception as e:
                siemplify.LOGGER.error('Failed to process alert {}'.format(alert.hash_id), alert_id=alert.hash_id)
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            siemplify.LOGGER.info('Finished processing Alert {}'.format(alert.hash_id), alert_id=alert.hash_id)

        if not is_test_run:
            siemplify.LOGGER.info("Saving existing ids.")
            utils.write_ids(siemplify, existing_ids)
            # Chronicle API doesn't work well with timelines, so we will just fetch whatever exists and process all
            # found alerts
            siemplify.save_timestamp(new_timestamp=now)

        siemplify.LOGGER.info('Created total of {} cases'.format(len(processed_alerts)))
        siemplify.LOGGER.info('------------------- Main - Finished -------------------')
        siemplify.return_package(processed_alerts)

    except Exception as err:
        siemplify.LOGGER.error('Got exception on main handler. Error: {}'.format(err))
        siemplify.LOGGER.exception(err)
        if is_test_run:
            raise


if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test)
