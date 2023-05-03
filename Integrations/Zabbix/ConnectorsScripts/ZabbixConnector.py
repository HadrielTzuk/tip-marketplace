# ============================================================================#
# title           :ZabbixConnector.py
# description     :This Module contain all Zabbix connector functionality, Fetch events by triggers (events that are caused by discovery rules and internal events are not supported and not fetched).
# author          :avital@siemplify.co
# date            :21-01-2018
# python_version  :2.7
# Product Version: 2.2 (Assumed by VM OS type)
# ============================================================================#

# ============================= IMPORTS ===================================== #
import sys
import datetime
from SiemplifyUtils import (
    convert_unixtime_to_datetime,
    output_handler
)
from SiemplifyConnectors import CaseInfo, SiemplifyConnectorExecution
from TIPCommon import (
    extract_connector_param,
    dict_to_flat,
    convert_datetime_to_unix_time,
    siemplify_fetch_timestamp,
    siemplify_save_timestamp,
    validate_timestamp,
    is_overflowed
)
from ZabbixManager import ZabbixManager

# ============================== CONSTS ===================================== #
VENDOR = PRODUCT = u"Zabbix"
DEFAULT_NAME = u"Unable to get name"
WILDCARD = u'*'
PRIORITIES = {
    u'1': 20,
    u'2': 40,
    u'3': 60,
    u'4': 80,
    u'5': 100
}

# ============================= CLASSES ===================================== #


class ZabbixConnectorException(Exception):
    pass


class ZabbixConnector(object):

    def __init__(self, connector_scope, zabbix_manager, tags={}):
        self.connector_scope = connector_scope
        self.logger = connector_scope.LOGGER
        self.zabbix_manager = zabbix_manager
        self.tags = tags

    @staticmethod
    def parse_whitelist_tags(whitelist):
        """
        Parse the tags from the whitelist
        :param whitelist: {list} The whitelist of the connector
        :return: {dict} The collected tags
        """
        tags = {}

        # Collect tags from whitelist
        for item in whitelist:
            tag, value = item.split(u":")
            tags[tag] = value

        return tags

    def get_triggers(self, last_success_time_ms, only_problematic=False):
        """
        Get alerts from Zabbix
        :param: last_success_time_ms: {int} Get only triggers that have changed their state after the given time (unix timestamp)
        :param: only_problematic: {bool} If set to true consider only triggers in problem state.
        :return: {list} List of found triggers
        """
        triggers = []

        # Get problematic triggers with their last event and filter them by given tags
        for trigger in self.zabbix_manager.get_triggers(problematic=only_problematic,
                                                        select_last_event=True,
                                                        last_change_since=last_success_time_ms / 1000):
            try:
                if self.tags:
                    # There are tags to filter
                    self.logger.info(u"Validating trigger against whitelisted tags.")

                    for tag_obj in trigger.get(u'tags', []):
                        tag = tag_obj.get(u'tag')
                        value = tag_obj.get(u'value')

                        if tag in self.tags.keys() and (value in self.tags[tag] or self.tags[tag] == WILDCARD):
                            # Trigger has passed the tags filter
                            self.logger.info(u"Trigger {} has a whitelisted tag.".format(trigger.get(u"triggerid")))
                            triggers.append(trigger)
                            break
                    else:
                        self.logger.info(u"Trigger {} doesn't have a whitelisted tag. Skipping".format(trigger.get(u"triggerid")))

                else:
                    triggers.append(trigger)

            except Exception as e:
                self.logger.error(u"Unable to process trigger {}".format(trigger.get(u'triggerid')))
                self.logger.exception(e)

        return triggers

    def get_trigger_last_event(self, trigger):
        """
        Get the last event of a given trigger
        :param trigger: {dict} The trigger info
        :return: {dict} The last event of the trigger
        """
        # Get the last event of the trigger and get its info
        event_id = trigger[u'lastEvent'][u'eventid']
        trigger_events = self.zabbix_manager.get_events(eventids=event_id)

        if not trigger_events:
            self.logger.info(u"No events found for trigger {}. Skipping.".format(trigger[u"triggerid"]))
            return

        event = trigger_events[0]
        event[u'trigger'] = trigger

        return event

    def get_events(self, triggers, is_test=False):
        """
        Get the events from the found triggers
        :param triggers: {list} The found triggers
        :param is_test: {bool} Whether this is a test run or not
        :return: {list} The events
        """
        events = []

        for trigger in triggers:
            try:
                event = self.get_trigger_last_event(trigger)

                if event and event not in events:
                    events.append(event)

            except Exception as e:
                self.logger.error(u"Unable to get events for trigger {}".format(trigger.get(u'triggerid')))
                self.logger.exception(e)

                if is_test:
                    raise

        return events

    def create_alert_info(self, event, is_test=False):
        """
        Create a CaseInfo from an event
        :param event: {dict} The event data
        :param is_test: {bool} Whether this is a test run or not
        :return: {CaseInfo} The newly created case info
        """
        # Create the alert
        case_info = CaseInfo()
        maintenance = False

        try:
            hosts = []

            for host in event[u'hosts']:
                host = self.zabbix_manager.get_hosts(hostids=host[u'hostid'])[0]

                if int(host.get(u'maintenance_status', 0)) == 1:
                    # Host is in maintenance - skip the event
                    maintenance = True

                hosts.append(host)

            event[u'hosts'] = hosts

        except Exception as e:
            self.logger.error(u"Unable to get hosts for alert {}".format(event[u"eventid"]))
            self.logger.exception(e)

            if is_test:
                raise

        if maintenance:
            # Skip the event
            self.logger.info(u"One or more of the event's host are in maintenance. Skipping event.")
            return

        try:
            name = event[u'trigger'][u'description']
        except Exception as e:
            self.logger.error(u"Unable to get alert name for {}".format(event[u"eventid"]))
            self.logger.exception(e)
            name = DEFAULT_NAME

        case_info.name = name
        case_info.identifier = event[u'eventid']

        case_info.ticket_id = case_info.identifier
        case_info.reason = case_info.name

        try:
            priority = PRIORITIES[event[u'trigger'][u'priority']]
        except Exception as e:
            self.logger.error(u"Unable to get priority for {}".format(event[u"eventid"]))
            self.logger.exception(e)
            priority = -1

        case_info.priority = priority
        case_info.device_vendor = VENDOR
        case_info.device_product = PRODUCT
        case_info.source_system_name = u"Custom"
        case_info.display_id = case_info.identifier

        case_info.rule_generator = case_info.name  # Expression is too long...
        case_info.environment = self.connector_scope.context.connector_info.environment

        self.connector_scope.LOGGER.info(u"Flattening event's data")

        # Flatter specific areas of the dict
        event = dict_to_flat(event)

        case_info.events = [event]

        # Timestamps in Zabbix are in seconds and not milliseconds
        event[u'start_time'] = event[u'end_time'] = int(event.get(u'clock', 1)) * 1000
        case_info.start_time = case_info.end_time = int(event.get(u'clock', 1)) * 1000

        return case_info


@output_handler
def main(is_test_run=False):
    connector_scope = SiemplifyConnectorExecution()
    connector_scope.script_name = u"Zabbix Connector"

    try:
        if is_test_run:
            connector_scope.LOGGER.info(u'***** This is an \"IDE Play Button\" \"Run Connector once\" test run ******')

        connector_scope.LOGGER.info(u'==================== Main - Param Init ====================')

        api_root = extract_connector_param(
            connector_scope,
            param_name=u'Api Root',
            input_type=unicode,
            is_mandatory=True,
            print_value=True
        )

        username = extract_connector_param(
            connector_scope,
            param_name=u'Username',
            input_type=unicode,
            is_mandatory=True,
            print_value=True
        )

        password = extract_connector_param(
            connector_scope,
            param_name=u'Password',
            input_type=unicode,
            is_mandatory=True,
            print_value=False
        )

        max_hours_backwards = extract_connector_param(
            connector_scope,
            param_name=u'Fetch Max Hours Backwards',
            input_type=int,
            default_value=1,
            is_mandatory=False,
            print_value=True
        )

        only_problematic = extract_connector_param(
            connector_scope,
            param_name=u'Only Problematic Triggers',
            input_type=bool,
            is_mandatory=False,
            default_value=False,
            print_value=True
        )

        verify_ssl = extract_connector_param(
            connector_scope,
            param_name=u'Verify SSL',
            default_value=False,
            input_type=bool,
            is_mandatory=True
        )

        connector_scope.LOGGER.info(u'------------------- Main - Started -------------------')

        last_success_time_datetime = validate_timestamp(
            siemplify_fetch_timestamp(connector_scope, datetime_format=True), max_hours_backwards
        )
        last_success_time_ms = convert_datetime_to_unix_time(last_success_time_datetime)

        connector_scope.LOGGER.info(
            u'Last success time: {}'.format(last_success_time_datetime.isoformat())
        )

        connector_scope.LOGGER.info(u"Connecting to Zabbix")
        zabbix_manager = ZabbixManager(api_root, username, password, verify_ssl)
        connector_scope.LOGGER.info(u"Successfully connected.")

        connector_scope.LOGGER.info(u"Parsing tags from whitelist.")
        tags = ZabbixConnector.parse_whitelist_tags(connector_scope.whitelist)
        connector_scope.LOGGER.info(u"Found {} tags.".format(len(tags.keys())))

        zabbix_connector = ZabbixConnector(
            connector_scope=connector_scope,
            zabbix_manager=zabbix_manager,
            tags=tags
        )

        # Get alerts
        connector_scope.LOGGER.info(u"Collecting triggers from Zabbix.")
        triggers = zabbix_connector.get_triggers(last_success_time_ms=last_success_time_ms,
                                                 only_problematic=only_problematic)
        connector_scope.LOGGER.info(u"Found {} active triggers.".format(len(triggers)))

        connector_scope.LOGGER.info(u"Collecting events for triggers.")
        events = zabbix_connector.get_events(triggers, is_test=is_test_run)
        connector_scope.LOGGER.info(u"Found {} events.".format(len(events)))

        processed_alerts = []
        alerts = []

        for event in events:
            try:
                # Process each Zabbix event ( = Siemplify Alert)
                connector_scope.LOGGER.info(u"Processing event {}.".format(event[u"eventid"]))
                _is_overflowed = False
                case_info = zabbix_connector.create_alert_info(event)

                if not case_info:
                    # Event was skipped due to a host in maintenance
                    continue

                processed_alerts.append(case_info)

                _is_overflowed = is_overflowed(
                    connector_scope,
                    alert_info=case_info,
                    is_test_run=is_test_run
                )

                if _is_overflowed:
                    connector_scope.LOGGER.info(
                        u'{alert_name}-{alert_identifier}-{environment}-{product} found as overflow event. Skipping...'
                        .format(
                            alert_name=case_info.rule_generator,
                            alert_identifier=case_info.ticket_id,
                            environment=case_info.environment,
                            product=case_info.device_product
                        )
                    )
                    continue

                else:
                    alerts.append(case_info)
                    connector_scope.LOGGER.info(u'Finished processing event {}'.format(event[u"eventid"]))

            except KeyError as error:
                connector_scope.LOGGER.error(u"Event's data is missing mandatory key: {key}".format(
                    key=error.message
                ))

                if is_test_run:
                    raise

            except Exception as e:
                connector_scope.LOGGER.error(u'Failed to process event {}'.format(event.get(u"eventid")))
                connector_scope.LOGGER.exception(e)

                if is_test_run:
                    raise

        if not is_test_run:
            if processed_alerts:
                new_timestamp = sorted(processed_alerts, key=lambda alert: alert.end_time)[-1].end_time
                siemplify_save_timestamp(connector_scope, new_timestamp=new_timestamp)
                connector_scope.LOGGER.info(
                    u'New timestamp {} has been saved'.format(convert_unixtime_to_datetime(new_timestamp).isoformat())
                )

        connector_scope.LOGGER.info(u'Created total of {} cases'.format(len(alerts)))
        connector_scope.LOGGER.info(u'------------------- Main - Finished -------------------')
        connector_scope.return_package(alerts)

    except Exception as e:
        connector_scope.LOGGER.error(e)
        connector_scope.LOGGER.exception(e)

        if is_test_run:
            raise


if __name__ == "__main__":
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test_run)
