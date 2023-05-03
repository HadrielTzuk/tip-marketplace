import datetime
import sys

import arrow

from EnvironmentCommon import GetEnvironmentCommonFactory
from FireEyeEXManager import FireEyeEXManager
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import output_handler, unix_now, dict_to_flat, convert_unixtime_to_datetime
from TIPCommon import (
    extract_connector_param,
    read_ids_by_timestamp,
    write_ids_with_timestamp,
    is_approaching_timeout,
    filter_old_ids,
    siemplify_save_timestamp,
    get_last_success_time
)
from consts import (
    ALERTS_CONNECTOR_NAME,
    DURATION,
    MAP_FILE,
    DEVICE_VENDOR,
    DEVICE_PRODUCT,
    ALERT_NAME,
    PRINT_TIME_FORMAT,
    HOURS_LIMIT_IN_IDS_FILE
)


def filter_recent_alerts(siemplify, alerts, max_minutes_backwards=5):
    filtered_alerts = []

    for alert in alerts:
        if alert.occurred_time_unix < arrow.utcnow().shift(minutes=-max_minutes_backwards).timestamp * 1000:
            filtered_alerts.append(alert)

        else:
            siemplify.LOGGER.info(
                u"Alert {} occurred in the last {} minutes ({}). Dropping.".format(alert.uuid, max_minutes_backwards,
                                                                                   alert.occurred))

    return filtered_alerts


def group_alerts(fetched_alerts):
    alert_groups = set(map(lambda alert: alert.email_id, fetched_alerts))
    grouped_alerts = [[alert for alert in fetched_alerts if alert.email_id == group] for group in alert_groups]
    # Sort groups by the occurred timeof the earliest alert in each group
    return sorted(grouped_alerts,
                  key=lambda alert_group: sorted(alert_group,
                                                 key=lambda alert: alert.occurred_time_unix)[0].occurred_time_unix)


def create_alert_info(environment_common, alerts_group):
    sorted_alerts_group = sorted(alerts_group, key=lambda alert: alert.occurred_time_unix)

    alert_info = AlertInfo()
    alert_info.display_id = sorted_alerts_group[0].uuid
    alert_info.ticket_id = sorted_alerts_group[0].uuid
    alert_info.name = ALERT_NAME
    alert_info.rule_generator = sorted_alerts_group[0].name
    alert_info.priority = max([alert.priority for alert in alerts_group])
    alert_info.start_time = sorted_alerts_group[0].occurred_time_unix
    alert_info.end_time = sorted_alerts_group[-1].occurred_time_unix

    alert_info.device_vendor = DEVICE_VENDOR
    alert_info.device_product = DEVICE_PRODUCT

    events = [alert.event for alert in sorted_alerts_group]
    alert_info.events = map(dict_to_flat, events)
    alert_info.environment = environment_common.get_environment(alert_info.events[0])

    return alert_info


@output_handler
def main(is_test_run):
    connector_starting_time = unix_now()
    alerts = []
    processed_alerts = []
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = ALERTS_CONNECTOR_NAME

    if is_test_run:
        siemplify.LOGGER.info(u'***** This is an \"IDE Play Button\" \"Run Connector once\" test run ******')

    siemplify.LOGGER.info(u'==================== Main - Param Init ====================')

    environment_field = extract_connector_param(
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

    username = extract_connector_param(
        siemplify,
        param_name=u'Username',
        input_type=unicode,
        is_mandatory=True,
        print_value=True
    )

    password = extract_connector_param(
        siemplify,
        param_name=u'Password',
        input_type=unicode,
        is_mandatory=True,
        print_value=False
    )

    verify_ssl = extract_connector_param(
        siemplify,
        param_name=u'Verify SSL',
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

    max_hours_backwards = extract_connector_param(
        siemplify,
        param_name=u'Fetch Max Hours Backwards',
        input_type=int,
        default_value=1,
        is_mandatory=False,
        print_value=True
    )

    if max_hours_backwards > 48:
        warn_msg = u"\"Fetch Max Hours Backwards\" Should be 48 or less due to API limitations. 48 will be used."
        siemplify.LOGGER.warn(warn_msg)
        max_hours_backwards = 48

    siemplify.LOGGER.info(u'------------------- Main - Started -------------------')

    try:
        environment_common = GetEnvironmentCommonFactory.create_environment_manager(
            siemplify,
            environment_field_name=environment_field,
            environment_regex_pattern=environment_regex,
            map_file=MAP_FILE
        )

        last_success_time_datetime = get_last_success_time(siemplify,
                                                           offset_with_metric={"hours": max_hours_backwards})
        siemplify.LOGGER.info(u'Last success time: {}'.format(last_success_time_datetime.strftime(PRINT_TIME_FORMAT)))

        # Read already existing alerts ids
        siemplify.LOGGER.info(u"Loading existing ids from IDS file.")
        existing_ids = read_ids_by_timestamp(siemplify, offset_in_hours=HOURS_LIMIT_IN_IDS_FILE)
        siemplify.LOGGER.info(u'Found {} existing ids in ids.json'.format(len(existing_ids)))

        siemplify.LOGGER.info(u"Connecting to FireEye EX.")
        ex_manager = FireEyeEXManager(
            api_root=api_root,
            username=username,
            password=password,
            verify_ssl=verify_ssl
        )

        siemplify.LOGGER.info(u"Fetching alerts.")

        fetched_alerts = ex_manager.get_alerts(
            duration=DURATION,
            info_level=u'extended',
            start_time=last_success_time_datetime
        )

        siemplify.LOGGER.info(u"Found {} alerts.".format(len(fetched_alerts)))

        siemplify.LOGGER.info(u"Filtering already processed alerts")
        new_ids = [alert.uuid for alert in fetched_alerts]
        filtered_alerts_ids = filter_old_ids(new_ids, existing_ids)
        filtered_alerts = [alert for alert in fetched_alerts if alert.uuid in filtered_alerts_ids]
        siemplify.LOGGER.info(u'Found {} new alerts'.format(len(filtered_alerts)))

        siemplify.LOGGER.info(u"Filtering too recent alerts")
        filtered_recent_alerts = filter_recent_alerts(siemplify, filtered_alerts, 5)
        siemplify.LOGGER.info(u"Filtered to {} alerts".format(len(filtered_recent_alerts)))

        siemplify.LOGGER.info(u"Grouping alerts.")
        grouped_alerts = group_alerts(filtered_recent_alerts)

        siemplify.LOGGER.info(
            u"Grouped into {} alert grouped based on subject, destination and sender".format(len(grouped_alerts))
        )

        for alert_group in grouped_alerts:
            try:
                if is_approaching_timeout(connector_starting_time, python_process_timeout):
                    siemplify.LOGGER.info(u'Timeout is approaching. Connector will gracefully exit.')
                    break

                siemplify.LOGGER.info(u'Processing alert group {}'.format(alert_group[0].email_id))
                siemplify.LOGGER.info(u"There are {} alerts in this group".format(len(alert_group)))

                existing_ids.update({alert.uuid: unix_now() for alert in alert_group})
                processed_alerts.extend(alert_group)

                is_overflowed = False
                siemplify.LOGGER.info(u'Creating AlertInfo for alert group {}'.format(alert_group[0].email_id))
                alert_info = create_alert_info(environment_common, alert_group)

                siemplify.LOGGER.info(u'Finished creating AlertInfo for alert group {}'.format(alert_group[0].email_id))

                try:
                    is_overflowed = siemplify.is_overflowed_alert(
                        environment=alert_info.environment,
                        alert_identifier=alert_info.ticket_id,
                        alert_name=alert_info.rule_generator,
                        product=alert_info.device_product
                    )

                except Exception as e:
                    error_msg = u"Failed to detect overflow for Alert Group {}".format(alert_group[0].email_id)
                    siemplify.LOGGER.error(error_msg)
                    siemplify.LOGGER.exception(e)

                    if is_test_run:
                        raise

                if is_overflowed:
                    siemplify.LOGGER.info(
                        u'{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping...'
                        .format(
                            alert_name=alert_info.rule_generator,
                            alert_identifier=alert_info.ticket_id,
                            environment=alert_info.environment,
                            product=alert_info.device_product
                        )
                    )
                    continue

                else:
                    alerts.append(alert_info)
                    info_msg = u'Finished processing alert group {} was created.'.format(alert_group[0].email_id)
                    siemplify.LOGGER.info(info_msg)

                if is_test_run:
                    siemplify.LOGGER.info(u'This is a TEST run. Only 1 alert group will be processed.')
                    break

            except Exception as e:
                siemplify.LOGGER.error(u'Failed to process alert group {}'.format(alert_group[0].email_id))
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

        if not is_test_run:
            if filtered_alerts:
                if processed_alerts:
                    # NOTICE - This logic might cause missed alerts. If the order of the EX alerts are:
                    # A A B B C C A A
                    # The after grouping the alert groups will be AAAA, BB, CC
                    # So if for some reason, only the first alert group was processed, then the timestamp that will
                    # be saved is the occurred time of the last A. Which means that in next iteration of the connector
                    # we will skip the B B C C EX alerts.
                    # Product team was notified but they decided that this is a rare situation, and that grouping
                    # feature is more important, and therefore we can take the risk.
                    new_timestamp = sorted(processed_alerts,
                                           key=lambda alert: alert.occurred_time_unix)[-1].occurred_time_unix
                    siemplify_save_timestamp(siemplify, new_timestamp)
                    siemplify.LOGGER.info(
                        u'New timestamp {} has been saved'
                        .format(convert_unixtime_to_datetime(new_timestamp).strftime(PRINT_TIME_FORMAT))
                    )

            else:
                if fetched_alerts:
                    # Alerts were found but none passed the existing ids filtering - this might mean that there are
                    # more than 200 alerts with the same timestamp, or that we got somehow into a loop.
                    # So to avoid looping forever, we will add 1 second to the timestamp to advance the timeline
                    siemplify.LOGGER.info(
                        u"No new alerts were found. Timestamp will be increased by 1 second to avoid looping forever"
                    )
                    last_success_time_datetime += datetime.timedelta(minutes=1)
                    siemplify_save_timestamp(siemplify, last_success_time_datetime)
                    siemplify.LOGGER.info(
                        u'New timestamp {} has been saved'.format(
                            last_success_time_datetime.strftime(PRINT_TIME_FORMAT)
                        )
                    )
                else:
                    siemplify.LOGGER.info(u"No alerts were fetched. Timestamp won't be updated.")

            write_ids_with_timestamp(siemplify, existing_ids)

        siemplify.LOGGER.info(u'Created total of {} AlertInfos'.format(len(alerts)))

        siemplify.LOGGER.info(u'------------------- Main - Finished -------------------')
        siemplify.return_package(alerts)

    except Exception as e:
        siemplify.LOGGER.error(e)
        siemplify.LOGGER.exception(e)

        if is_test_run:
            raise e


if __name__ == '__main__':
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test)
