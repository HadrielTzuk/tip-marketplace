from SiemplifyUtils import output_handler
from QRadarManager import QRadarManager
from QRadarCommon import QRadarCommon
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import CaseInfo
from SiemplifyUtils import convert_unixtime_to_datetime, convert_datetime_to_unix_time, utc_now
from TIPCommon import (
    extract_connector_param,
    dict_to_flat,
    siemplify_fetch_timestamp,
    siemplify_save_timestamp,
    is_overflowed,
)
from UtilsManager import (
    get_case_priority_by_event_magnitude,
    load_events_data,
    write_events_data,
    get_environment_for_correlations_connector
)
from exceptions import QRadarCorrelationsEventsConnectorException
import uuid
import sys
import datetime
import collections
import arrow

# CONSTANTS
FIRST_TIME_OFFENSE_KEY_NAME = "first_time"
MAX_TIME_FOR_REFETCHING = 5  # minutes
OLD_OFFENSE_SHIFT = 60  # minutes


class QRadarCorrelationsEventsConnector(object):
    """
    QRadar Correlations Events Connector
    """

    def __init__(self, connector_scope):
        self.connector_scope = connector_scope
        self.logger = self.connector_scope.LOGGER
        self.common = QRadarCommon()

    def filter_offenses_by_events_count(self, offenses):
        """
        Check for offense events count, get only offenses with new events (local filter)
        :param events_data_file_path: {str} Path of the events data file
        :param offenses: {list of dicts}
        :return: {list of dicts} filtered_offenses
        """
        filtered_offenses = []

        events_data = load_events_data(self.connector_scope)
        events_data_keys = list(events_data.keys())

        for offense in offenses:
            offense_id = str(offense.id)
            events_count = int(offense.event_count or 0)
            if offense_id not in events_data_keys and events_count != 0:
                # An offense is not in events_data and it doesn't have 0
                # events reported in qradar - the offense is new. Add it to the
                # filtered_offenses list but mark it as a new offense to fetch
                # all of its events
                offense.raw_data[FIRST_TIME_OFFENSE_KEY_NAME] = True
                filtered_offenses.append(offense)
            elif int(events_data.get(offense_id, {}).get('count', 0)) != events_count:
                # The offense's local count is not updated - meaning either the
                # offense was really updated, or not all of the events were
                # fetched in previous cycles. Add it to filtered_offenses.
                filtered_offenses.append(offense)

        return filtered_offenses

    @staticmethod
    def validate_timestamp_offset(time_stamp_unixtime, offset_in_days=2):
        """
        Validate if timestamp in offset range.
        :param time_stamp_unixtime: {long}
        :param offset_in_days: {integer}
        :return: unixtime: if time not in offset return offset time {long}
        """
        offset_datetime = utc_now() - datetime.timedelta(days=offset_in_days)
        # Convert offset time to unixtime.
        offset_time_unixtime = convert_datetime_to_unix_time(offset_datetime)

        if time_stamp_unixtime < offset_time_unixtime:
            return offset_time_unixtime

        return time_stamp_unixtime

    @staticmethod
    def calculate_case_priority_by_magnitude(events_list):
        """
        Calculate Siemplify priority.
        :param events_list: list of dicts when each dict is an event {list}
        :return: case priority {integer}
        """
        # Get max magnitude.
        max_magnitude = 0
        for event in events_list:
            event_magnitude = float(event.get('magnitude', max_magnitude))
            if event_magnitude > max_magnitude:
                max_magnitude = event_magnitude

        return get_case_priority_by_event_magnitude(float(max_magnitude))

    def create_case_package(self, offense_id, rule_name, events_list, environment, connector_scope):
        """
        Create case package.
        :param offense_id: QRadar offense id {string}
        :param rule_name: QRadar rule {string}
        :param events_list: list of dicts when each dict is an event {list}
        :param environment:
        :param connector_scope:
        :return: Siemplify case object {caseInfo}
        """
        self.logger.info("Creating CaseInfo for {} - {}".format(offense_id, rule_name))

        case_info = CaseInfo()
        #  sort events by start time.

        events_list = sorted(events_list, key=lambda event: event.get('startTime', 1))

        case_info.start_time = int(events_list[0].get("startTime", 1))
        case_info.end_time = int(events_list[-1].get("endTime", 1))
        case_info.description = "Offence ID: {0}, Rule Name: {1}".format(offense_id, rule_name)
        case_info.ticket_id = "{offense_id}_{rule_name}_{start_time}_{end_time}".format(
            offense_id=offense_id,
            rule_name=rule_name,
            start_time=case_info.start_time,
            end_time=case_info.end_time)
        case_info.environment = get_environment_for_correlations_connector(connector_scope, environment)
        case_info.display_id = "{0}_{1}".format(case_info.ticket_id, uuid.uuid4())
        case_info.name = rule_name
        case_info.rule_generator = rule_name
        # QRadar cases based on events so there always has to be event at the list.
        case_info.device_product = events_list[0].get("deviceProduct", "Error Getting Device Product")
        case_info.device_vendor = self.common.get_category_human_readable_value(events_list[0].get('category'))
        case_info.priority = self.calculate_case_priority_by_magnitude(events_list)

        # Add the offense_id and the offense updated time (last event) in order to sync Qradar offenses with Siemplify
        case_info.extensions.update({'offense_id': offense_id})
        case_info.source_grouping_identifier = offense_id

        # Flat events data.
        try:
            case_info.events = list(map(dict_to_flat, events_list))
        except Exception as e:
            self.logger.error("Unable to flatten events: {}".format(e))
            self.logger.exception(e)
            case_info.events = []

        return case_info

    def filter_events_per_rule(self, events, whitelist, events_limit_per_rule):
        """
        Arrange all events in a dict per rule and filter them by the giving whitelist
        :param events: {dict} events to arrange and filter
        :param whitelist: {list} rules to include (if empty all rules will be included)
        :param events_limit_per_rule: {int}
        :return: {dict} events per rule ex.-{<rulename>:[<event1>,<event2>]}
        """
        result_dict = collections.defaultdict(list)

        for event in events:
            event_name = event.name if event.name else "Can't get event name"
            self.logger.info('Processing event: {}'.format(event_name))
            rulename_field_name = 'rulename_creEventList' if 'rulename_creEventList' in \
                                                             event.raw_data else 'rulename_creEventList'.lower()
            for rule in event.raw_data[rulename_field_name]:
                if len(result_dict[rule]) < events_limit_per_rule:
                    if rule in whitelist or not whitelist:
                        result_dict[rule].append(event.to_json())
                        self.logger.info("Add event to caseinfo of rule {}".format(rule))
                    else:
                        self.logger.warn("Event's rule {} not in whitelist. not including event in this rule's "
                                         "caseinfo.".format(rule))
                else:
                    self.logger.warn("Reached event count limit for rule {}. Skipping event.".format(rule))

        # Remove empty values
        return {rule: events for rule, events in result_dict.items() if events}


@output_handler
def main(is_test_run=False):
    """
    QRadar connector main
    :param is_test_run: run test flow of real flow (timestamp updating is the difference)
    :return:
    """
    connector_scope = SiemplifyConnectorExecution()
    qradar_connector = QRadarCorrelationsEventsConnector(connector_scope)
    output_variables = {}
    log_items = []
    cases = []

    try:
        if is_test_run:
            connector_scope.LOGGER.info(" ------------ Starting Qradar Connector test. ------------ ")

        else:
            connector_scope.LOGGER.info(" ------------ Starting Connector. ------------ ")

        # Parameters.
        api_root = extract_connector_param(
            connector_scope,
            param_name="API Root",
            is_mandatory=True,
            print_value=True
        )

        api_token = extract_connector_param(
            connector_scope,
            param_name="API Token",
            is_mandatory=True,
            print_value=False
        )

        api_version = extract_connector_param(
            connector_scope,
            param_name="API Version",
            print_value=True
        )

        custom_fields = extract_connector_param(
            connector_scope,
            param_name="Custom Fields",
            default_value='',
            print_value=True
        )

        events_limit_per_offence = extract_connector_param(
            connector_scope,
            param_name="Events Limit Per Offense",
            is_mandatory=True,
            input_type=int,
            print_value=True
        )

        event_limit_per_rule = extract_connector_param(
            connector_scope,
            param_name="Event Limit Per Rule",
            is_mandatory=True,
            input_type=int,
            print_value=True
        )

        max_days_backwards = extract_connector_param(
            connector_scope,
            param_name="Max Days Backwards",
            default_value=1,
            input_type=int,
            print_value=True
        )

        max_offenses_per_cycle = extract_connector_param(
            connector_scope,
            param_name="Max Offenses Per Cycle",
            default_value=5,
            input_type=int,
            print_value=True
        )

        use_qradar_environments = extract_connector_param(
            connector_scope,
            param_name="Use QRadar Environments",
            is_mandatory=True,
            input_type=bool,
            print_value=True
        )

        whitelist = connector_scope.whitelist

        connector_scope.LOGGER.info('Connection to QRadar')

        qradar_manager = QRadarManager(api_root, api_token, api_version)

        try:
            saved_timestamp = siemplify_fetch_timestamp(siemplify=connector_scope)
        except Exception as e:
            connector_scope.LOGGER.error("An error as occurred while fetching saved timestamp. Resetting timestamp.")
            connector_scope.LOGGER.exception(e)
            saved_timestamp = 1

        last_timestamp = qradar_connector.validate_timestamp_offset(
            saved_timestamp,
            offset_in_days=max_days_backwards)

        # End time for the event query (AQL STOP query value)
        current_time = utc_now()
        last_hour = arrow.utcnow().shift(hours=-1).timestamp * 1000
        fetch_time = min(last_timestamp, last_hour)
        # Get updated offenses.
        connector_scope.LOGGER.info('Starting fetching updated offenses since: {0}'.format(
            datetime.datetime.fromtimestamp(fetch_time / 1000)))

        try:
            all_offenses = qradar_manager.get_updated_offenses_from_time(fetch_time)
            connector_scope.LOGGER.info('Found {0} updated offenses with ids: {1}.'.format(
                len(all_offenses),
                [offense.id for offense in all_offenses])
            )

        except Exception as err:
            raise QRadarCorrelationsEventsConnectorException(
                'Error fetching updated offenses since {0}, ERROR: {1}'.format(fetch_time, err))

        # Fetch the current local event's data (event count per offense,
        # and last event found of that offense)
        events_data = load_events_data(connector_scope)

        # Filter out the offenses that need processing
        offenses_to_process = qradar_connector.filter_offenses_by_events_count(all_offenses)

        connector_scope.LOGGER.info(
            'Filtered to {0} updated offenses with new events with ids: {1}.'.format(
                len(offenses_to_process),
                [offense.id for offense in offenses_to_process]
            )
        )
        # Sort and slice the found offenses
        connector_scope.LOGGER.info("Slicing offenses to {0} offenses".format(max_offenses_per_cycle))

        offenses_to_process = sorted(offenses_to_process, key=lambda offense: offense.last_updated_time)
        offenses_to_process = offenses_to_process[:max_offenses_per_cycle]

        connector_scope.LOGGER.info("Final selected offenses: {}"
                                    .format([offense.id for offense in offenses_to_process]))

        if is_test_run:
            if offenses_to_process:
                offenses_to_process = offenses_to_process[:1]

        for offense in offenses_to_process:
            offense_id = offense.id
            offense_id_str = str(offense_id)

            # If Use QRadar Environments - try to resolve the domain_id of Qradar
            if use_qradar_environments:
                try:
                    offense_tenant = qradar_manager.get_domain_name_by_id(
                        offense.domain_id) or connector_scope.context.connector_info.environment
                except Exception as e:
                    connector_scope.LOGGER.error("Unable to resolve domain {}".format(offense.domain_id))
                    connector_scope.LOGGER.exception(e)
                    offense_tenant = connector_scope.context.connector_info.environment

            else:
                # If not Use QRadar Environments - set environment of offense to default
                offense_tenant = connector_scope.context.connector_info.environment

            # Get rules and their events by offense id.
            # Result is a dict where the rules are the keys and the events are the value.
            connector_scope.LOGGER.info('Processing on offense with id: {0}'.format(offense_id))

            try:
                max_days_backwards_timestamp = qradar_connector.validate_timestamp_offset(1, max_days_backwards)

                if offense.raw_data.get(FIRST_TIME_OFFENSE_KEY_NAME):
                    # Offense is a new one - get its all events from timestamp 1
                    # up to max days backwards
                    connector_scope.LOGGER.info("Offense {} has been seen first the first time.".format(offense_id))
                    offense_last_success_time = max_days_backwards_timestamp

                else:
                    offense_last_success_time = int(events_data.get(offense_id_str, {}).get(
                        'last_event', max_days_backwards_timestamp))

                connector_scope.LOGGER.info(
                    "Fetching events for offense {} since: {}".format(offense_id, datetime.datetime.fromtimestamp(
                        offense_last_success_time / 1000)))

                last_success_time_datetime = convert_unixtime_to_datetime(offense_last_success_time)

                events = qradar_manager.get_events_by_offense_id(offense_id,
                                                                 custom_fields,
                                                                 offense_last_success_time,
                                                                 last_success_time_datetime,
                                                                 current_time,
                                                                 events_limit_per_offence,
                                                                 max_days_backwards)

                connector_scope.LOGGER.info("Found {} events.".format(len(events)))

                if offense.raw_data.get(FIRST_TIME_OFFENSE_KEY_NAME, False):
                    # Offense is new (seen first time) - set its local count
                    # as the number of total events of the offense in Qradar.
                    # Update the last_event to be the unixtime stamp of the
                    # latest found event
                    events_data[offense_id_str] = {
                        'count': int(offense.event_count or 0),
                        'last_event': sorted(
                            events, key=lambda event: event.start_time or 1)[-1].start_time if events else 1
                    }

                else:
                    # The offense is known - add the number of found events
                    # in the current cycle to the local event count.
                    # Update the last_event to be the unixtime stamp of the
                    # latest found event
                    events_data[offense_id_str] = {
                        'count': int(events_data.get(offense_id_str, {}).get('count', 0)) + len(events),
                        'last_event': sorted(events, key=lambda event: event.start_time or 1)[-1].start_time
                        if events else
                        events_data[offense_id_str]['last_event']
                    }

                connector_scope.LOGGER.info("Filtering events by whitelist.")

                # Filter adn arrange events by rules
                events_for_rules = qradar_connector.filter_events_per_rule(events, whitelist, event_limit_per_rule)

                connector_scope.LOGGER.info("Found {0} whitelisted rules for offense with id {1}, the rules are: {2}"
                                            .format(len(events_for_rules), offense_id, ","
                                                    .join(events_for_rules.keys())))

            except Exception as err:
                connector_scope.LOGGER.error('Error fetching events for offense with id: {0}, ERROR: {1}'.format(
                    offense_id,
                    err))
                connector_scope.LOGGER.exception(err)

                if is_test_run:
                    raise

                # Add empty case with offense id and no events
                connector_scope.LOGGER.info("Creating empty case with offense id and no events or data")
                empty_events_list = [{}]
                case = qradar_connector.create_case_package(offense.id, "Cannot fetch events for offense",
                                                            empty_events_list,
                                                            environment=offense_tenant,
                                                            connector_scope=connector_scope)
                cases.append(case)
                # Move on to the next offense
                continue

            # Create case package.
            for rule_name, events_for_rule in events_for_rules.items():
                connector_scope.LOGGER.info('Running on rule "{0}" from offense: {1}'.format(rule_name, offense_id))
                if events_for_rule:
                    try:
                        case = qradar_connector.create_case_package(offense.id, rule_name,
                                                                    events_for_rule,
                                                                    environment=offense_tenant,
                                                                    connector_scope=connector_scope)

                        if not is_overflowed(connector_scope, case, is_test_run):
                            cases.append(case)
                            connector_scope.LOGGER.info(
                                'Created case package for rule "{0}" with offense id {1} with display id:{2}'.format(
                                    rule_name,
                                    offense_id,
                                    case.display_id
                                ))

                        else:
                            connector_scope.LOGGER.warn(
                                "{alertname}-{alertid}-{environ}-{product} found as overflow alert, skipping this "
                                "alert.".format(
                                    alertname=case.name,
                                    alertid=case.ticket_id,
                                    environ=case.environment,
                                    product=case.device_product
                                )
                            )

                    except Exception as err:
                        connector_scope.LOGGER.error(
                            'Error creating case package for rule "{0}" with offense id: {1} , ERROR: {2}'.format(
                                rule_name,
                                offense_id,
                                err
                            ))
                        connector_scope.LOGGER.exception(err)

                        if is_test_run:
                            raise

                else:
                    connector_scope.LOGGER.info('No events found for rule: "{0}"'.format(rule_name))

        if is_test_run:
            connector_scope.LOGGER.info(" ------------ Finish Qradar Connector Test ------------ ")
        else:
            # Save the updated of events data to file
            write_events_data(connector_scope, events_data)
            siemplify_save_timestamp(siemplify=connector_scope, new_timestamp=current_time)
            connector_scope.LOGGER.info(" ------------ Connector Finished Iteration ------------ ")

        connector_scope.return_package(cases, output_variables, log_items)

    except Exception as err:
        connector_scope.LOGGER.error('Got exception on main handler. Error: {0}'.format(err))
        connector_scope.LOGGER.exception(err)
        if is_test_run:
            raise


if __name__ == '__main__':
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test_run=is_test_run)
