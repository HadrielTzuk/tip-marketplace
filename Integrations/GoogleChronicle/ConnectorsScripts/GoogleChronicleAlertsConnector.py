import sys
import json
from collections import defaultdict
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
CONNECTOR_NAME = 'Google Chronicle - Alerts Connector'
HOURS_LIMIT_IN_IDS_FILE = 72
TIMEOUT_THRESHOLD = 0.9


@output_handler
def main(is_test_run):
    connector_starting_time = unix_now()
    processed_alerts = []
    all_alerts = []
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
        siemplify.LOGGER.info("Fetching Asset Alerts since {}".format(utils.datetime_to_rfc3339(last_success_time)))

        # The Chronicle API brings the alerts in descending order, to we can't use fetch limit or we might miss alerts
        # Instead we need to fetch as much alerts as we can and process all of them
        fetched_alerts = manager.list_alerts(start_time=utils.datetime_to_rfc3339(last_success_time),
                                             limit=consts.MAX_LIMIT)[0]
        filtered_alerts = utils.filter_old_alerts(siemplify.LOGGER, fetched_alerts, existing_ids, id_key='hash_id')
        filtered_alerts = sorted(filtered_alerts, key=lambda filtered_alert: filtered_alert.start_time)

        siemplify.LOGGER.info(
            "Found {} new Asset Alerts in since {} (out of {} fetched).".format(len(filtered_alerts),
                                                                                last_success_time.isoformat(),
                                                                                len(fetched_alerts)))

        if is_test_run:
            siemplify.LOGGER.info('This is a TEST run. Only 1 alert will be processed.')
            filtered_alerts = filtered_alerts[:1]

        for alert in filtered_alerts:
            try:
                if utils.is_approaching_timeout(python_process_timeout, connector_starting_time, TIMEOUT_THRESHOLD):
                    siemplify.LOGGER.info('Timeout is approaching. Connector will gracefully exit.')
                    break

                siemplify.LOGGER.info('Started processing Asset Alert {}'.format(alert.hash_id), alert_id=alert.hash_id)

                existing_ids.update({alert.hash_id: unix_now()})

                alert_infos = build_alerts(alert, siemplify, environment_field_name, environment_regex_pattern)

                # Add alert infos to all alerts (regardless of overflow status) to mark it as processed
                all_alerts.extend(alert_infos)
                non_overflow_alert_infos = []

                for alert_info in alert_infos:
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
                    non_overflow_alert_infos.append(alert_info)

                siemplify.LOGGER.info(
                    '{} AlertInfos for Asset Alert {} were created.'.format(len(non_overflow_alert_infos), alert.hash_id))

            except Exception as e:
                siemplify.LOGGER.error('Failed to process Asset Alert {}'.format(alert.hash_id), alert_id=alert.hash_id)
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            siemplify.LOGGER.info('Finished processing Asset Alert {}'.format(alert.hash_id), alert_id=alert.hash_id)

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


def build_alerts(alert, siemplify, environment_field_name, environment_regex_pattern):
    """
    Build Siemplify AlertInfos out of asset alert
    :param alert: {datamodels.Alert} The asset alert
    :param siemplify: {SiemplifyConnectorExecution} Siemplify context
    :param environment_field_name: {str} The name of the field to get the environment from
    :param environment_regex_pattern: {str} The regex pattern to apply on the environment value
    :return: {list} List of created Siemplify AlertInfo.
    """
    if not alert.alert_infos:
        siemplify.LOGGER.info(f"Asset {alert.asset} doesn't have any alert infos. Skipping.")
        return []

    environment_common = utils.get_environment_common(siemplify, environment_field_name, environment_regex_pattern)
    siemplify.LOGGER.info(f"Creating AlertInfos for asset {alert.asset}")

    if len(alert.alert_infos) == 1:
        # The asset has single alert info - so this alert info will be both the alert in Siemplify and the event
        # The asset has single alert info - so this alert info will be both the alert in Siemplify and the event
        siemplify.LOGGER.info(f"Asset {alert.asset} has only 1 alert info. Creating AlertInfo out of it.")

        siemplify.LOGGER.info("Asset ID: {}, Asset: {}, Alert Name: {}, Product: {}. Severity: {}".format(
            alert.hash_id, alert.asset, alert.alert_infos[0].name,
            alert.alert_infos[0].source_product, alert.alert_infos[0].siemplify_severity,
        ))
        return [alert.alert_infos[0].as_alert_info(alert.asset, [alert.alert_infos[0].as_event()], environment_common)]

    siemplify.LOGGER.info(
        f"Asset {alert.asset} has {len(alert.alert_infos)} alert info. Grouping them into AlertInfos.")

    # In case there are multiple alert infos for the asset - we will group the alert infos by the name of the alert info
    groups = defaultdict(list)

    for asset_alert_info in alert.alert_infos:
        groups[asset_alert_info.name].append(asset_alert_info)

    siemplify_alert_infos = []

    for alert_info_group in groups.values():
        # Calculate edge timestamps within the group (start and end time)
        sorted_alert_infos = sorted(alert_info_group, key=lambda alert_info: alert_info.timestamp_ms)
        start_time = sorted_alert_infos[0].timestamp_ms
        end_time = sorted_alert_infos[-1].timestamp_ms

        # Build the events out of the group
        events = [asset_alert_info.as_event() for asset_alert_info in alert_info_group]

        # Build the Siemplify Alert, where the Siemplify alert will be the first asset alert info in the group
        # and the events are all the alert infos in the group
        siemplify.LOGGER.info(f"Creating AlertInfo for asset {alert.asset} and alert info name {alert_info_group[0].name} with {len(events)} events.")
        siemplify.LOGGER.info("Asset ID: {}, Asset: {}, Alert Name: {}, Product: {}. Severity: {}".format(
            alert.hash_id, alert.asset, alert_info_group[0].name,
            alert_info_group[0].source_product, alert_info_group[0].siemplify_severity,
        ))

        siemplify_alert_infos.append(
            alert_info_group[0].as_alert_info(alert.asset, events, environment_common, start_time, end_time)
        )

    return siemplify_alert_infos


if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test)
