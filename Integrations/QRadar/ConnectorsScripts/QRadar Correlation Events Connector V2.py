import sys
import json
import copy
import uuid
import hashlib
import arrow
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import output_handler, convert_datetime_to_unix_time, convert_unixtime_to_datetime, unix_now
from TIPCommon import (
    extract_connector_param,
    siemplify_fetch_timestamp,
    validate_timestamp,
    string_to_multi_value,
    read_content,
    WHITELIST_FILTER,
    BLACKLIST_FILTER,
    TIMEOUT_THRESHOLD
)
from BaseIntegrationClasses import BaseConnector, QRadarLoggerWrapper
from QRadarCommon import QRadarCommon
from exceptions import QRadarConnectorValidationException, QRadarCustomFieldValidation, QRadarInvalidRuleException
from constants import (
    QRADAR_CORRELATION_EVENTS_CONNECTOR_V2_SCRIPT_NAME,
    DEFAULT_DOMAIN,
    RULE_ID_NAME_MAPPING_DB_KEY,
    RULE_ID_NAME_MAPPING_FILE,
    CORRELATIONS_CONNECTOR_V2_NAME,
    DEFAULT_ORDER_BY_KEY,
    DEFAULT_SORT_ORDER
)
from UtilsManager import load_offense_events, save_offense_events, create_rule_mapping


# CONSTANTS
ALERT_REQUIRED_FIELDS = ("custom_rule", "offense_description")
DEFAULT_MAX_HOURS_BACKWARDS = 24
STOPPED_TIMER = -1
FAILED_TO_FETCH_EVENTS = "Cannot Fetch Events for the Offense"
ONE_MINUTE_UNIX_TIMESTAMP = 60_000


class QradarCorrelationEventsConnectorV2(BaseConnector):
    def __init__(self):
        """
        Create an instance of the connector
        """
        self.common = None

        BaseConnector.__init__(self, QRADAR_CORRELATION_EVENTS_CONNECTOR_V2_SCRIPT_NAME)
        self.rule_names_mapping = {}
        self.offense_events = {}
        # This param will hold the new timestamp for the connector to save
        # The param will be updated to the last_updated_time of the last processed offense

    def set_connector_logger(self):
        self.logger = QRadarLoggerWrapper(
            self.logger,
            debug_logging=self.params.debug_logging
        )

    def load_manager(self):
        if float(self.params.api_version) >= 10.1:
            from QRadarManagerV10 import QRadarV10Manager
            return QRadarV10Manager(self.params.api_root, self.params.api_token, self.params.api_version,
                                    logger=self.logger)
        else:
            from QRadarManager import QRadarManager
            return QRadarManager(self.params.api_root, self.params.api_token, self.params.api_version)

    def load_common_classes(self):
        """
        Load the common classes of the connector
        """
        self.common = QRadarCommon()

    def load_connector_configuration(self):
        """
        Load the connector configurations
        """
        self.params.python_process_timeout = extract_connector_param(
            siemplify=self.siemplify,
            param_name="PythonProcessTimeout",
            input_type=int,
            is_mandatory=True,
            print_value=True
        )

        self.params.api_root = extract_connector_param(
            self.siemplify,
            param_name="API Root",
            is_mandatory=True,
            print_value=True
        )

        self.params.api_token = extract_connector_param(
            self.siemplify,
            param_name="API Token",
            is_mandatory=True,
            print_value=False
        )

        self.params.api_version = extract_connector_param(
            self.siemplify,
            param_name="API Version",
            print_value=True
        )

        self.params.events_page_size = extract_connector_param(
            self.siemplify,
            param_name="Connector Events Page Size",
            is_mandatory=True,
            input_type=int,
            print_value=True
        )

        self.params.offenses_limit_per_cycle = extract_connector_param(
            self.siemplify,
            param_name="Max Offenses per Cycle",
            is_mandatory=True,
            input_type=int,
            print_value=True
        )

        self.params.events_limit_per_alert = extract_connector_param(
            self.siemplify,
            param_name="Events Limit per Siemplify Alert",
            is_mandatory=True,
            input_type=int,
            print_value=True
        )

        self.params.offenses_padding_period = extract_connector_param(
            self.siemplify,
            param_name="Offenses Padding Period",
            is_mandatory=True,
            input_type=int,
            print_value=True
        )

        self.params.events_padding_period = extract_connector_param(
            self.siemplify,
            param_name="Events Padding Period",
            is_mandatory=True,
            input_type=int,
            print_value=True
        )

        self.params.max_hours_backwards = extract_connector_param(
            self.siemplify,
            param_name="Max Hours Backwards",
            is_mandatory=False,
            input_type=int,
            default_value=DEFAULT_MAX_HOURS_BACKWARDS,
            print_value=True
        )

        self.params.custom_fields = extract_connector_param(
            self.siemplify,
            param_name="Custom Fields",
            print_value=True
        )

        self.params.environment_field_name = extract_connector_param(
            self.siemplify,
            param_name="Environment Field Name",
            print_value=True
        )

        self.params.environment_regex = extract_connector_param(
            self.siemplify,
            param_name="Environment Regex Pattern",
            print_value=True
        )

        self.params.whitelist_as_blacklist = extract_connector_param(
            self.siemplify,
            param_name="Use whitelist as a blacklist",
            print_value=True,
            is_mandatory=True,
            default_value=False,
            input_type=bool
        )

        self.params.whitelist_filter_type = BLACKLIST_FILTER if self.params.whitelist_as_blacklist else WHITELIST_FILTER

        self.params.disable_overflow = extract_connector_param(
            self.siemplify,
            param_name="Disable Overflow",
            print_value=True,
            default_value=False,
            input_type=bool
        )

        self.params.offense_rule_events_limit = extract_connector_param(
            self.siemplify,
            param_name="Events Limit per Qradar Offense Rule",
            print_value=True,
            input_type=int
        )

        self.params.events_query_limit = extract_connector_param(
            self.siemplify,
            param_name="Events Limit for Connector to Query in One Connector Run",
            print_value=True,
            input_type=int
        )

        self.params.alert_name_field_name = extract_connector_param(
            self.siemplify,
            param_name="What Value to use for the Name Field of Siemplify Alert?",
            print_value=True
        )

        self.params.rule_generator_field_name = extract_connector_param(
            self.siemplify,
            param_name="What Value to use for the Rule Generator Field of Siemplify Alert?",
            print_value=True
        )
        self.params.domain_filter = extract_connector_param(
            self.siemplify,
            param_name="Domain Filter",
            is_mandatory=False,
            print_value=True
        )
        self.params.domain_filter_list = list(set(string_to_multi_value(self.params.domain_filter)))

        self.params.qradar_offense_rules_resync_timer = extract_connector_param(
            self.siemplify,
            param_name="Qradar Offense Rules Re-Sync Timer",
            print_value=True,
            input_type=int,
            default_value=0
        )
        self.validate_positive_integer_params(self.params.qradar_offense_rules_resync_timer,
                                              "Qradar Offense Rules Re-Sync Timer",
                                              can_be_zero=True)

        self.params.debug_logging = extract_connector_param(
            self.siemplify,
            param_name="Debug Logging",
            print_value=True,
            input_type=bool,
            default_value=False
        )

        self.params.create_empty_cases = False

        self.validate_alert_name_field_name()
        self.validate_rule_generator_field_name()
        self.validate_events_limit_per_rule()

    def validate_positive_integer_params(self, input_param, name: str, can_be_zero: bool):
        if input_param is not None:
            if not can_be_zero and input_param == 0:
                raise QRadarConnectorValidationException("'{}' must be a number bigger than 0".format(name))
        if input_param < 0:
                raise QRadarConnectorValidationException("'{}' must be a number bigger or equal to 0".format(name))

    def validate_events_limit_per_rule(self):
        """
        Validate rule events limit parameters
        return: {void} exception in case of inconsistent limits
        """
        if self.params.offense_rule_events_limit and self.params.events_query_limit \
                and self.params.events_query_limit < self.params.offense_rule_events_limit:
            self.logger.error("Value provided for the \"Events Limit per Qradar Offense Rule\" can't be bigger than "
                              "value for \"Events Limit for Connector to Query in One Connector Run\"")
            raise QRadarConnectorValidationException("Value provided for the \"Events Limit per Qradar Offense Rule\" "
                                                     "can't be bigger than value for \"Events Limit for Connector to "
                                                     "Query in One Connector Run\"")

    def load_rule_names_mappings(self):
        """
        Load rule names to ID mapping from file (or generate new mapping if needed)
        :return: {dict} The rule names mapping, in the following format:
        {
          "rules_id_name_mapping":{
            "latest_whitelist_hashsum":"43c94f5b6a0b1202c118a874c626e461",
            "is_whitelist_as_blacklist": true,
            "last_update_timestamp": unixtime
            "mapping":{
                "100224":"Local: SSH or Telnet Detected on Non-Standard Port",
                "100051":"Multiple Login Failures from the Same Source",
                "100045":"AssetExclusion: Exclude NetBIOS Name By MAC Address",
                "100046":"Login Failure to Disabled Account",
                "100205":"Destination Network Weight is Low",
                "100211":"Source Network Weight is Low",
                "100209":"Context Is Local to QRADAR _ DONT USE"
            }
          }
        }
        """
        if self.rule_names_mapping:
            self.logger.debug("Rule names mapping's already fetched.")
            return

        current_mapping = read_content(
            self.siemplify, RULE_ID_NAME_MAPPING_FILE, RULE_ID_NAME_MAPPING_DB_KEY, {"is_empty": "true"})

        if current_mapping == {"is_empty": "true"}:
            self.logger.info("Rule names mapping file doesn't exist. Creating new rule names mapping.")
            current_mapping = create_rule_mapping(
                siemplify=self.siemplify,
                is_whitelist_as_blacklist=self.is_whitelist_as_blacklist(),
                calculate_hash=self.calculate_whitelist_hash(),
                rules=self.manager.list_rules(),
                connector_name=CORRELATIONS_CONNECTOR_V2_NAME,
                logger=self.logger
            )
        else:
            try:
                mapping_expired = (
                        unix_now() - current_mapping.get("rules_id_name_mapping", {}).get("last_update_timestamp") >
                        self.params.qradar_offense_rules_resync_timer * ONE_MINUTE_UNIX_TIMESTAMP
                )
                if self.is_whitelist_changed(current_mapping.get("rules_id_name_mapping", {})
                                                         .get("latest_whitelist_hashsum")):
                    self.logger.info('Whitelist has changed. Creating new rule names mapping.')
                    current_mapping = create_rule_mapping(
                        siemplify=self.siemplify,
                        is_whitelist_as_blacklist=self.is_whitelist_as_blacklist(),
                        calculate_hash=self.calculate_whitelist_hash(),
                        rules=self.manager.list_rules(),
                        connector_name=CORRELATIONS_CONNECTOR_V2_NAME,
                        logger=self.logger
                    )
                elif self.is_whitelist_as_blacklist_changed(
                        current_mapping.get("rules_id_name_mapping", {})
                                .get("is_whitelist_as_blacklist", False)):
                    self.logger.info(
                        '\"Use whitelist as a blacklist\" parameter was changed. Creating new rule names mapping.')
                    current_mapping = create_rule_mapping(
                        siemplify=self.siemplify,
                        is_whitelist_as_blacklist=self.is_whitelist_as_blacklist(),
                        calculate_hash=self.calculate_whitelist_hash(),
                        rules=self.manager.list_rules(),
                        connector_name=CORRELATIONS_CONNECTOR_V2_NAME,
                        logger=self.logger
                    )

                elif mapping_expired:
                    self.logger.info(f"More then {self.params.qradar_offense_rules_resync_timer} minutes past since "
                                     f"the last update of the rule mapping. Creating new rule mapping")
                    current_mapping = create_rule_mapping(
                        siemplify=self.siemplify,
                        is_whitelist_as_blacklist=self.is_whitelist_as_blacklist(),
                        calculate_hash=self.calculate_whitelist_hash(),
                        rules=self.manager.list_rules(),
                        connector_name=CORRELATIONS_CONNECTOR_V2_NAME,
                        logger=self.logger
                    )
            except Exception as e:

                if isinstance(e, QRadarInvalidRuleException):
                    raise Exception("Connector failed to run because the  offense rule(s) provided in the whitelist"
                                    " section (dynamic list) is (are) not valid.")
                self.logger.error("Unable to read rule name mappings file: {}".format(e))
                self.logger.exception(e)
                self.logger.info("Creating new rule names mapping")
                current_mapping = create_rule_mapping(
                    siemplify=self.siemplify,
                    is_whitelist_as_blacklist=self.is_whitelist_as_blacklist(),
                    calculate_hash=self.calculate_whitelist_hash(),
                    rules=self.manager.list_rules(),
                    connector_name=CORRELATIONS_CONNECTOR_V2_NAME,
                    logger=self.logger
                )

        if not current_mapping["rules_id_name_mapping"]["mapping"]:
            self.logger.error("No valid rules found in the whitelist. Please add rules. Aborting")
            raise Exception("No valid rules found in the whitelist. Please add rules. Aborting")

        self.rule_names_mapping = current_mapping

    def validate_alert_name_field_name(self):
        """
        Validate the value passed to the Name Field of Siemplify Alert configuration
        :return: {bool} True if valid, exception otherwise
        """
        if self.params.alert_name_field_name not in ALERT_REQUIRED_FIELDS:
            raise QRadarConnectorValidationException('Valid values to use for the Name Field of Siemplify Alert are {}'
                                                     .format(' or '.join(ALERT_REQUIRED_FIELDS)))

        return True

    def validate_rule_generator_field_name(self):
        """
        Validate the value passed to the Rule Generator Field of Siemplify Alert configuration
        :return: {bool} True if valid, exception otherwise
        """
        if self.params.rule_generator_field_name not in ALERT_REQUIRED_FIELDS:
            raise QRadarConnectorValidationException(
                'Valid values to use for the Rule Generator Field of Siemplify Alert are {}'
                    .format(' or '.join(ALERT_REQUIRED_FIELDS)))

        return True

    def alert_id_repr(self, offense):
        """
        Get the alert's ID representation (in this case - the ID of the offense)
        :param offense: {Offense} The offense
        :return: {int} The offense ID
        """
        return offense.id

    def calculate_whitelist_hash(self):
        """
        Calculate the current whitelist md5 hash
        :return: {unicode} The md5 of the whitelist
        """
        return hashlib.md5(json.dumps(sorted(self.siemplify.whitelist)).encode()).hexdigest()

    def is_whitelist_as_blacklist(self):
        """
        Check if whitelist is used as blacklist
        :return: {bool} True if whitelist is used as blacklist, otherwise False
        """
        return bool(self.params.whitelist_filter_type == BLACKLIST_FILTER)

    def is_whitelist_changed(self, current_hash):
        """
        Check if the whitelist has changed from previous runs by comparing its hash
        :param current_hash: {unicode} The currently saved hash of the whitelist (saved in previous run)
        :return: {bool} True if changed, otherwise False.
        """
        return current_hash != self.calculate_whitelist_hash()

    def is_whitelist_as_blacklist_changed(self, current_whitelist_as_blacklist_flag):
        """
        Check if "Use whitelist as a blacklist" parameter was changed from previous runs
        :param current_whitelist_as_blacklist_flag: {bool} The currently saved whitelist as blacklist boolean flag (saved in previous run)
        :return: {bool} True if changed, otherwise False.
        """
        return current_whitelist_as_blacklist_flag != self.params.whitelist_as_blacklist

    def fetch_last_success_time(self):
        """
        Fetch the last success time of the connector.
        The last success time will be either the last updated time of the newest processed offense,
        ot (NOW - max_hours_backwards param)
        :return:
        """
        try:
            saved_timestamp = siemplify_fetch_timestamp(siemplify=self.siemplify, datetime_format=True)
        except Exception as e:
            self.logger.error("An error as occurred while fetching saved timestamp. Resetting timestamp.")
            self.logger.exception(e)
            saved_timestamp = convert_unixtime_to_datetime(1)

        return validate_timestamp(
            saved_timestamp,
            offset_in_hours=self.params.max_hours_backwards
        )

    def pre_processing(self):
        """
        Perform some pre-processing in the connector
        """
        # Load rule names mapping
        self.load_rule_names_mappings()
        # Load already seen events hashes
        self.offense_events = load_offense_events(self.siemplify, self.params.events_padding_period)

        # If the offense padding period has changed or last timestamp is earlier than the padding period (means that
        # either the offenses were not updated in a long time, or the connector has stopped for a certain period) -
        # reset all the timers to avoid false positive empty cases
        if self.is_offense_padding_changed():
            self.logger.info("Offense padding has changed. Resetting all timers.")
            self.reset_timers()

        # Add +1 to padding period to make sure that if a real timer has really exceeded, we will create an empty case
        # for it, and it won't be missed because of this condition.
        elif self.last_success_time_datetime < arrow.utcnow().shift(minutes=-self.params.offenses_padding_period + 1):
            self.logger.info(
                "Last success time of connector is older than the offense padding period. Resetting all timers"
            )
            self.reset_timers()

        self.logger.info(
            "Stopping timers for CLOSED offenses that were updated in the offense padding period."
        )

        closed_updated_offenses = self.get_updated_closed_offenses()
        # Get only the closed offenses that have active timers
        closed_updated_offenses = [offense for offense in closed_updated_offenses
                                   if not self.is_timer_stopped(offense.id)]

        self.logger.info(
            "Found {} updated offenses that are CLOSED and have active timers.".format(len(closed_updated_offenses))
        )

        for closed_offense in closed_updated_offenses:
            self.logger.info(
                "Offense {} was updated and is CLOSED. Stopping its timer.".format(closed_offense.id)
            )
            self.stop_offense_timer(closed_offense.id)

    def post_processing(self):
        """
        Perform some post-processing in the connector
        """
        # Save the updated events hashes to the offense events file
        self.save_filtered_offense_events()

    def save_event_to_offense_events(self, offense, rule_id, event):
        """
        Save an event to the offense_events.json file (mark event as already seen to avoid duplicates)
        :param offense: {Offense} The offense of the event
        :param rule_id: {int} The ID of the rule that the event triggered
        :param event: {Event} The event to save
        """
        event_hash = event.as_hash()
        offense_id = str(offense.id)
        rule_id = str(rule_id)

        # If the offense is new
        if offense_id not in list(self.offense_events["offenses"].keys()):
            # Offense was never in the offense events file. Need to create new record
            self.logger.debug(f"Offense {offense_id} is new for offenses file, creating an entry.")
            self.offense_events["offenses"][offense_id] = {
                "last_update_time": offense.last_updated_time,
                "no_new_events_timer_start_time": STOPPED_TIMER,
                "rules": {
                    rule_id: {
                        "events": {
                            event_hash: unix_now()
                        }
                    }
                }
            }
        # If the rule is new
        elif rule_id not in self.offense_events["offenses"][offense_id]["rules"]:
            self.logger.debug(f"Rule {rule_id} is new for offense {offense_id}")
            self.offense_events["offenses"][offense_id]["rules"][rule_id] = {
                "events": {
                    event_hash: unix_now()
                }
            }
        # If the event is new
        elif event_hash not in self.offense_events["offenses"][offense_id]["rules"][rule_id]["events"]:
            self.logger.debug(f"Event with hash {event_hash} is new for offense {offense_id}")
            # Event is seen for the first time for the offense
            self.offense_events["offenses"][offense_id]["rules"][rule_id]["events"][event_hash] = unix_now()

        # Update the last_update_time of the offense
        self.offense_events["offenses"][offense_id]["last_update_time"] = offense.last_updated_time

        if not self.offense_events["offenses"][offense_id].get("total_events_collected_per_rule"):
            self.offense_events["offenses"][offense_id]["total_events_collected_per_rule"] = {}

        total = self.offense_events["offenses"][offense_id]["total_events_collected_per_rule"].get(rule_id) or 0
        self.offense_events["offenses"][offense_id]["total_events_collected_per_rule"][rule_id] = total + 1

    def save_filtered_offense_events(self):
        """
        Save the offense events file
        """
        # Before writing the new events - filter the old events hashes
        self.logger.debug("Filtering old events hashes")
        self.offense_events = self.filter_old_offense_events()
        # Update the last_offense_padding_period to the current's run offense padding period
        self.offense_events["last_offense_padding_period"] = self.params.offenses_padding_period
        # Saving events to db\file dynamically
        save_offense_events(self.siemplify, self.params.offenses_padding_period, self.offense_events)

    def filter_old_offense_events(self):
        """
        Filter old events hashes from the offense events to prevent the file from getting too big
        :return: {dict} Filtered offense events dict
        """
        filtered_offense_events = copy.deepcopy(self.offense_events)

        # Calculate the time limit beyond which an event hash will be considered old
        # The limit is equal to NOW - 2 * max(events_padding_period, max_hours_backwards) to guarantee that a needed hash
        # won't be deleted too soon
        time_limit = (
            arrow
            .utcnow()
            .shift(days=-max(self.params.events_padding_period, self.params.max_hours_backwards / 24))
            .timestamp
        ) * 1000

        # In each offense id
        for offense_id in map(str, self.offense_events["offenses"].keys()):
            # In each rule
            for rule_id in self.offense_events["offenses"][offense_id]["rules"]:
                # In each event item
                for event_hash, timestamp in \
                        self.offense_events["offenses"][offense_id]["rules"][rule_id]["events"].items():
                    if timestamp < time_limit:
                        del filtered_offense_events["offenses"][offense_id]["rules"][rule_id]["events"][event_hash]

        return filtered_offense_events

    def start_offense_timer(self, offense_id, restart_timer=False):
        """
        Start the "failed to fetch events" timer for the given offense.
        A timer should be started in one of the following cases:
        - An exception occurred while fetching events for an offense (any rule)
        - No events fetched at all for the offense (from all ruled together)
        If a timer was already started for the offense - nothing will be done unless restart_timer is set to True
        :param offense_id: {int} The ID of the offense to start the timer for
        :param restart_timer: {bool} Override and restart existing started timer
        """
        offense_id = str(offense_id)

        if offense_id not in list(self.offense_events["offenses"].keys()):
            # Offense was never in the offense events file. Need to create new record
            self.offense_events["offenses"][offense_id] = {
                "last_update_time": 0,
                "no_new_events_timer_start_time": unix_now(),
                "rules": {}
            }

        if restart_timer or self.offense_events["offenses"][offense_id]["no_new_events_timer_start_time"] == \
                STOPPED_TIMER:
            # Only start new timer if there is timer is not already started, or if restart timer is True
            self.offense_events["offenses"][offense_id]["no_new_events_timer_start_time"] = unix_now()

    def stop_offense_timer(self, offense_id):
        """
        End the "failed to fetch events" timer for the given offense.
        A timer should be stopped if:
        - Offense Padding Period has changed since last connector run
        - Events were successfully fetched for at least one rule
        - Timer exceeded and empty AlertInfo was created
        :param offense_id: {int} The ID of the offense to end the timer for
        """
        offense_id = str(offense_id)

        if offense_id not in list(self.offense_events["offenses"].keys()):
            # Offense was never in the offense events file. Need to create new record
            self.offense_events["offenses"][offense_id] = {
                "last_update_time": 0,
                "no_new_events_timer_start_time": STOPPED_TIMER,
                "rules": {}
            }

        else:
            self.offense_events["offenses"][offense_id]["no_new_events_timer_start_time"] = STOPPED_TIMER

    def reset_timers(self):
        """
        Reset all "failed to fetch events" timers for all offenses
        """
        for offense_id in map(str, self.offense_events["offenses"].keys()):
            self.offense_events["offenses"][offense_id]["no_new_events_timer_start_time"] = STOPPED_TIMER

    def is_offense_padding_changed(self):
        """
        Check if Offense Padding Period param has changed since previous run
        :return: {bool} True if changed, False otherwise
        """
        if not self.offense_events:
            self.offense_events = load_offense_events(self.siemplify, self.params.events_padding_period)

        return self.params.offenses_padding_period != int(self.offense_events["last_offense_padding_period"])

    def is_timer_stopped(self, offense_id):
        """
        Check if the timer of a given offense is stopped or not
        :param offense_id: {int} The ID of the offense
        :return: {bool} True if stopped, False otherwise
        """
        offense_id = str(offense_id)

        if offense_id not in self.offense_events["offenses"]:
            # No timer was initialized ever
            return True

        if self.offense_events["offenses"][offense_id]["no_new_events_timer_start_time"] == STOPPED_TIMER:
            # Timer is stopped
            return True

        return False

    def is_timer_exceeded(self, offense_id):
        """
        Check if the timer of a given offense has timed out or not
        :param offense_id: {int} The ID of the offense
        :return: {bool} True if timed out, False otherwise
        """
        offense_id = str(offense_id)

        if offense_id not in self.offense_events["offenses"]:
            # No timer was initialized ever
            return False

        if self.offense_events["offenses"][offense_id]["no_new_events_timer_start_time"] == STOPPED_TIMER:
            # Timer is stopped
            return False

        # If the no_new_events_timer_start_time timestamp of the offense is smaller (earlier) than (NOW - offenses_padding_period)
        # then the timer has exceeded
        return (
            self.offense_events["offenses"][offense_id]["no_new_events_timer_start_time"] <
            arrow.utcnow().shift(minutes=-self.params.offenses_padding_period).timestamp * 1000
        )

    def get_timed_out_offenses_ids(self):
        """
        Get the IDS of the offenses that timed out
        :return: {list} List of IDS of timed out offenses
        """
        offense_ids = []
        for offense_id in list(self.offense_events["offenses"].keys()):
            if self.is_timer_exceeded(offense_id):
                offense_ids.append(offense_id)

        return offense_ids

    def process_timed_out_offenses(self):
        """
        Process timed out offenses - create an empty AlertInfo for them and stop their timers
        :return: {[AlertInfo]} The created empty AlertInfo objects
        """
        alerts = []
        for offense_id in self.get_timed_out_offenses_ids():
            try:
                self.logger.info(
                    "Offense {} \"Failed to fetch events\" timer has timed out. Creating empty AlertInfo.".format(
                        offense_id)
                )
                alert_info = self.create_failed_to_fetch_events_alert_info(offense_id)
                alerts.append(alert_info)
                self.stop_offense_timer(offense_id)

            except Exception as e:
                self.logger.error("Failed to process timed out offense {}".format(offense_id))
                self.logger.exception(e)

        return alerts

    def get_updated_closed_offenses(self):
        """
        Get updated offenses from QRadar in the matching searching period that are closed.
        The searching period is determined by the offenses_padding_period and the last success time of the connector.
        :return: {list} The found closed updated offenses, up to offenses_limit_per_cycle param limit
        """
        # Pick the earlier between (NOW - offenses_padding_period) and last success time (up to Max Days Backwards)
        last_hour = arrow.utcnow().shift(minutes=-self.params.offenses_padding_period).datetime
        fetch_time = min(self.last_success_time_datetime, last_hour)

        self.logger.info("Fetching closed updated offenses since {}".format(fetch_time.isoformat()))
        # Fetch the updated offenses in the search period, sorted by last update time
        return self.manager.get_updated_offenses_from_time(
            timestamp_unix_time=convert_datetime_to_unix_time(fetch_time),
            status="CLOSED",
            connector_starting_time=self.connector_starting_time,
            python_process_timeout=self.params.python_process_timeout
        )

    def get_alerts_to_process(self):
        """
        Get updated offenses from QRadar in the matching searching period.
        The searching period is determined by the offenses_padding_period and the last success time of the connector.
        :return: {list} The found updated offenses, up to offenses_limit_per_cycle param limit
        """
        # Pick the earlier between (NOW - offenses_padding_period) and last success time (up to Max Days Backwards)
        last_hour = arrow.utcnow().shift(minutes=-self.params.offenses_padding_period).datetime
        fetch_time = min(self.last_success_time_datetime, last_hour)
        domain_ids = []
        self.logger.info("Fetching updated offenses since {}".format(fetch_time.isoformat()))
        # Fetch the updated offenses in the search period, sorted by last update time

        if self.params.domain_filter_list:
            all_domains = self.manager.get_domains()
            domains_name_to_id = {domain.name: domain.id for domain in all_domains}
            invalid_domains = []
            for domain in self.params.domain_filter_list:
                if domain == DEFAULT_DOMAIN:
                    domain_ids.append(0)
                elif domain in domains_name_to_id:
                    domain_ids.append(domains_name_to_id[domain])
                else:
                    invalid_domains.append(domain)
            if invalid_domains:
                raise QRadarConnectorValidationException(
                    f"Following values for \"Domain Filter\" parameter were not found in QRadar: {', '.join(invalid_domains)}.")

        return self.manager.get_updated_offenses_from_time(
            timestamp_unix_time=convert_datetime_to_unix_time(fetch_time),
            domain_ids=domain_ids,
            connector_starting_time=self.connector_starting_time,
            python_process_timeout=self.params.python_process_timeout
        )

    def get_rule_name_by_id(self, rule_id):
        """
        Get rule name by the rule ID
        :param rule_id: {int} The rule ID
        :return: {unicode} The rule name
        """
        self.load_rule_names_mappings()

        return self.rule_names_mapping.get("rules_id_name_mapping", {}).get("mapping", {}).get(str(rule_id))

    def get_already_seen_events_hashes(self, offense, rule_id):
        """
        Get the already seen events hashes for a given offense and rule id
        :param offense: {Offense} The offense to get the hashes for
        :param rule_id: {int} The rule id to get the events for
        :return: {[unicode]} List of already seen hashes
        """
        offense_id = str(offense.id)
        rule_id = str(rule_id)
        return (
            self.offense_events["offenses"]
                .get(offense_id, {})
                .get("rules", {})
                .get(rule_id, {})
                .get("events", {}).keys()
        )

    def is_whitelisted_rule_id(self, rule_id):
        """
        Check if a given rule ID is whitelisted or not (by lookup in the rules mapping)
        :param rule_id: {int} The ID of the rule
        :return: {bool} True if whitelisted, False otherwise.
        """
        return str(rule_id) in list(self.rule_names_mapping.get("rules_id_name_mapping", {}).get("mapping", {}).keys())

    def is_rule_id_passed_whitelist_filter(self, rule_id):
        """
        Check if a given rule ID passed whitelist filters.
        :param rule_id: {int} The ID of the rule
        :return: {bool} True if passed whitelist, otherwise False
        """
        return str(rule_id) in list(self.rule_names_mapping.get("rules_id_name_mapping", {}).get("mapping", {}).keys())

    def is_whitelisted_alert(self, offense):
        """
        Check if the offense is whitelisted or not. An offense will be considered whitelisted if it is triggered by
        at least one whitelisted rule
        :param offense: {Offense} The offense
        :return: {bool} True if whitelisted, False otherwise
        """
        self.logger.info(
            "Offense {} rules: {}".format(offense.id, ", ".join([str(rule_id) for rule_id in offense.rule_ids]))
        )

        for rule_id in offense.rule_ids:
            if self.is_whitelisted_rule_id(rule_id):
                return True

        return False

    def is_passed_whitelist_filters(self, offense):
        """
        Check if the offense is whitelisted or not. An offense will be considered whitelisted if it is triggered by
        at least one whitelisted rule
        :param offense: {Offense} The offense
        :return: {bool} True if whitelisted, False otherwise
        """
        self.logger.info(
            "Offense {} rules: {}".format(offense.id, ", ".join([str(rule_id) for rule_id in offense.rule_ids]))
        )

        for rule_id in offense.rule_ids:
            if self.is_whitelisted_rule_id(rule_id):
                return True

        return False

    def is_approaching_timeout(self):
        """
        Check if a timeout is approaching.
        :return: {bool} True if timeout is close, False otherwise
        """
        processing_time_ms = unix_now() - self.connector_starting_time
        return processing_time_ms > self.params.python_process_timeout * 1000 * TIMEOUT_THRESHOLD

    def process_alerts(self, fetched_offenses, is_test_run):
        """
        This method handles the processing of fetched offenses.
        For each offense, processes the offense and creates AlertInfo for each whitelisted rule in the offense that
        had events.
        This method had to be overwritten because as opposed to normal connectors that create a single AlertInfo per
        alert, the QRadar connector creates multiple AlertInfo, per rule in the offense.
        :param fetched_offenses: {[Offense]} The fetched offenses
        :param is_test_run: {bool} Whether the current run of the connector is a test run or not
        :return: ([AlertInfo], [AlertInfo]) All created AlertInfo objects, only the processed AlertInfo (non-overflowed)
        """
        all_alerts = []
        processed_alerts = []
        processed_offenses_count = 0

        for index, fetched_offense in enumerate(fetched_offenses):
            try:
                if self.is_approaching_timeout():
                    self.logger.info("Timeout is approaching. Connector will gracefully exit.")
                    break

                # Perform pre processing on the current alert
                self.alert_pre_processing(fetched_offense)

                if not self.is_passed_whitelist_filters(fetched_offense):
                    self.logger.info("Offense {} did not pass whitelist filter. Skipping."
                                     .format(self.alert_id_repr(fetched_offense) or "#{}".format(index)))
                    continue

                # Process a single alert - create an AlertInfo
                alert_infos = self.process_alert(fetched_offense, index)

                if alert_infos:
                    processed_offenses_count += 1

                for alert_info in alert_infos:
                    # Determine if the alert is an overflowed alert or not
                    is_overflow = self.is_overflow_alert(alert_info, is_test_run) \
                        if not self.params.disable_overflow else False

                    if not is_overflow:
                        # The alert is not an overflow - add it to processed alert
                        processed_alerts.append(alert_info)

                    # Perform post processing on the current alert
                    self.alert_post_processing(fetched_offense, alert_info, is_overflow)

                    all_alerts.append(alert_info)

                self.logger.info('Finished processing offense {}.'
                                 .format(self.alert_id_repr(fetched_offense) or "#{}".format(index)))

                self.logger.debug("Offense {} last update time: {}".format(
                    self.alert_id_repr(fetched_offense) or "#{}".format(index),
                    convert_unixtime_to_datetime(fetched_offense.last_updated_time).isoformat()
                ))
                self.processed_offenses.append(fetched_offense)

                if processed_offenses_count >= self.params.offenses_limit_per_cycle:
                    self.logger.info("Reached max amount of offenses per cycle limit. Aborting.")
                    break

                if is_test_run:
                    self.logger.info("This is a TEST run. Only 1 offense is processed.")
                    break

            except Exception as e:
                self.logger.error(
                    "Failed to process offense {}".format(self.alert_id_repr(fetched_offense) or "#{}".format(index))
                )
                if isinstance(e, QRadarCustomFieldValidation):
                    raise Exception("Connector failed to run because provided Custom Fields caused Qradar AQL query "
                                    "validation error. Please make sure that the Custom Fields are provided without "
                                    "errors and exist in Qradar events table.")
                self.logger.exception(e)

                if is_test_run:
                    raise

        return all_alerts, processed_alerts

    def process_alert(self, offense, index):
        """
        This method handles the processing of a single offense.
        This method fetches the events of the offense for each whitelist rule of the offense and creates an AlertInfo
        out of the offense and the matching rule and its events.
        This method had to be overwritten because as opposed to normal connectors, QRadar connector has another layer
        - alerts (offenses), rules and events.
        :param offense: The fetched offense
        :param index: {int} The index of the alert within all the fetched alerts in the current connector cycle
        :return: {AlertInfo} The created AlertInfo for the alert
        """
        processed_alerts = []
        total_events_count = 0

        self.logger.info(
            "Processing offense {}".format(self.alert_id_repr(offense) or "#{}".format(index))
        )

        for rule_id in offense.rule_ids:
            if self.is_approaching_timeout():
                # Need to gracefully exit
                break

            if self.is_rule_id_passed_whitelist_filter(rule_id):
                rule_name = self.get_rule_name_by_id(rule_id)

                try:
                    if self.is_events_limit_per_offense_rule_reached(offense.id, rule_id):
                        self.logger.info(f"Events limit for {str(offense.id)} offense {rule_id} {rule_name} rule is "
                                         f"reached. Skipping")
                        continue

                    self.logger.info(
                        "Fetching events of offense {}, rule: {} ({})".format(
                            self.alert_id_repr(offense) or "#{}".format(index),
                            rule_name,
                            rule_id
                        )
                    )

                    # Fetch the events of the offense for the current rule
                    events = self.get_events_for_rule(
                        offense,
                        rule_id,
                        self.calculate_events_min_limit(offense.id, rule_id),
                        self.get_already_seen_events_hashes(offense, rule_id)
                    )

                    for event in events:
                        self.save_event_to_offense_events(offense, rule_id, event)

                    events_len = len(events)
                    total_events_count += events_len

                    if events:
                        self.logger.info("Found {} events for rule {} ({}). Stopping timer."
                                         .format(events_len, rule_name, rule_id))
                        self.logger.info("Creating an AlertInfo for rule {} ({})"
                                         .format(rule_name, rule_id))
                        # Create an AlertInfo object for the offense and rule
                        processed_alerts.append(self.create_alert_info(offense, events, rule_name))

                        # Stop the "failed to fetch events" timer for the offense
                        self.stop_offense_timer(offense.id)

                    else:
                        self.logger.info("No events were found for rule {} ({})"
                                         .format(rule_name, rule_id))
                        continue

                    self.logger.info("Finished processing rule {} ({}) of offense {}"
                                     .format(rule_name, rule_id, offense.id))

                except Exception as e:
                    # Start the "failed to fetch events" timer for the offense.
                    self.start_offense_timer(offense.id)
                    self.logger.error("Failed fetching events of alert {} for rule {}. Starting timer."
                                      .format(self.alert_id_repr(offense) or "#{}".format(index), rule_name))
                    if isinstance(e, QRadarCustomFieldValidation):
                        raise QRadarCustomFieldValidation()
                    self.logger.exception(e)

            else:
                self.logger.info('Rule {} did not pass whitelist filter. Skipping'.format(rule_id))

        if not total_events_count:
            # TODO: maybe we need to remove this one as this will cause many false positives
            # No events were found for any of the whitelisted rules - starting timer.
            # If for a long period (current offense padding period), there will be no new events, we will
            self.logger.info('No events were found for offense {} from all rules. Starting timer.'
                             .format(self.alert_id_repr(offense) or "#{}".format(index)))
            self.start_offense_timer(offense.id)

        return processed_alerts

    def get_events_for_rule(self, offense, rule_id, limit=None, existing_events_hashes=[]):
        """
        Get events for an offense and a specific rule
        :param offense: {Offense} The offense to fetch events for
        :param rule_id: {int} The rule id to fetch events for
        :param limit: {int} Max amount of events to fetch
        :param existing_events_hashes: {[]} List of already seen events hashes
        :return: {[Event]} List of events
        """
        return self.manager.get_events_by_offense_id(
            offense_id=offense.id,
            log_source_ids=[str(log_source_id) for log_source_id in offense.log_source_ids],
            rules_ids=[str(rule_id)],
            custom_fields=self.params.custom_fields,
            events_period_padding=self.params.events_padding_period,
            limit=limit,
            existing_events_hashes=existing_events_hashes,
            page_size=self.params.events_page_size,
            total_limit_of_events_per_offense=self.params.events_query_limit,
            order_by_key=DEFAULT_ORDER_BY_KEY,
            sort_order=DEFAULT_SORT_ORDER
        )

    def create_alert_info(self, offense, events, rule_name=None):
        """
        Creatw an AlertInfo object from a single alert and its activities
        :param offense: {Offense} An offense instance
        :param rule_name: {unicode} The rule name that triggered the events
        :param events: [Event] A list of the events objects related to the offense
        :return: {AlertInfo} The created alert info object
        """
        alert_info = AlertInfo()

        # Set the times of the AlertInfo based on the oldest and newest events in it
        events = sorted(events, key=lambda item: item.start_time or 1)
        alert_info.start_time = int(events[0].start_time or 1)
        alert_info.end_time = int(events[-1].end_time or 1)

        alert_info.ticket_id = "{offense_id}_{rule_name}_{start_time}_{end_time}".format(
            offense_id=offense.id,
            rule_name=rule_name,
            start_time=alert_info.start_time,
            end_time=alert_info.end_time
        )
        alert_info.display_id = "{0}_{1}".format(alert_info.ticket_id, uuid.uuid4())
        alert_info.name = rule_name if self.params.alert_name_field_name == "custom_rule" else offense.description
        alert_info.rule_generator = rule_name if self.params.rule_generator_field_name == "custom_rule" else \
            offense.description
        alert_info.priority = offense.priority
        alert_info.description = "Offence ID: {0}, Rule Name: {1}".format(offense.id, rule_name)
        alert_info.device_product = events[0].device_product if events else "Error Getting Device Product"
        alert_info.device_vendor = self.common.get_category_human_readable_value(events[0].category if events else None)
        alert_info.environment = self.environment_common.get_environment(offense.as_extension())
        alert_info.source_grouping_identifier = offense.id
        alert_info.extensions.update(offense.as_extension())
        alert_info.extensions.update(
            {
                "rule_name": rule_name,
                'offense_id': offense.id
            }
        )

        # Flat events data.
        try:
            alert_info.events = [event.as_event() for event in events]
        except Exception as e:
            self.logger.error("Unable to flatten events: {}".format(e))
            self.logger.exception(e)
            alert_info.events = []

        return alert_info

    def create_failed_to_fetch_events_alert_info(self, offense_id):
        """
        Create an "empty" AlertInfo object for an offense that we failed to fetch events for (for a long time)
        :param offense_id: {int} The ID of the offense to create the empty alert for
        :return: {AlertInfo} The created alert info object
        """
        alert_info = AlertInfo()
        alert_info.start_time = 1
        alert_info.end_time = 1

        alert_info.ticket_id = "{offense_id}_{rule_name}_{start_time}_{end_time}".format(
            offense_id=offense_id,
            rule_name=FAILED_TO_FETCH_EVENTS,
            start_time=alert_info.start_time,
            end_time=alert_info.end_time
        )
        alert_info.display_id = "{0}_{1}".format(alert_info.ticket_id, uuid.uuid4())
        alert_info.name = FAILED_TO_FETCH_EVENTS
        alert_info.rule_generator = FAILED_TO_FETCH_EVENTS
        alert_info.priority = -1
        alert_info.description = "Offence ID: {0}, Rule Name: {1}".format(offense_id, FAILED_TO_FETCH_EVENTS)
        alert_info.device_product = "Error Getting Device Product"
        alert_info.device_vendor = self.common.DEFAULT_CATEGORY
        alert_info.environment = self.siemplify.context.connector_info.environment
        alert_info.source_grouping_identifier = offense_id
        alert_info.events = []
        alert_info.extensions.update(
            {
                "rule_name": self.FAILED_TO_FETCH_EVENTS,
                'offense_id': offense_id
            }
        )
        return alert_info

    def is_events_limit_per_offense_rule_reached(self, offense_id, rule_id):
        """
        Check whether enough amount of events were already fetched for the offense rule
        :param offense_id: {int} The ID of the offense
        :param rule_id: {int} The ID of the offense rule
        :return: True if already reached limit, False otherwise
        """
        if not self.params.offense_rule_events_limit:
            return False

        total_events_per_rule = self.offense_events.get("offenses", {}).get(str(offense_id), {})\
            .get("total_events_collected_per_rule", {}).get(str(rule_id), 0)

        if total_events_per_rule and total_events_per_rule >= self.params.offense_rule_events_limit:
            return True

        return False

    def calculate_events_min_limit(self, offense_id, rule_id):
        """
        Calculate events min limit based on events_limit_per_alert and offense_rule_events_limit parameters
        :param offense_id: {int} The ID of the offense
        :param rule_id: {int} The ID of the offense rule
        :return: {int} min limit for events
        """
        if not self.params.offense_rule_events_limit:
            return self.params.events_limit_per_alert

        total_events_per_rule = self.offense_events.get("offenses", {}).get(str(offense_id), {})\
            .get("total_events_collected_per_rule", {}).get(str(rule_id), 0)

        return min(self.params.events_limit_per_alert, self.params.offense_rule_events_limit - total_events_per_rule)


@output_handler
def main():
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    connector = QradarCorrelationEventsConnectorV2()
    connector.run(is_test_run, process_single_alert_on_test=False)


if __name__ == '__main__':
    main()
