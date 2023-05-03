import copy
import hashlib
import json

import sys
import uuid
import arrow
from BaseIntegrationClasses import BaseConnector, QRadarLoggerWrapper
from QRadarCommon import QRadarCommon
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import convert_datetime_to_unix_time, convert_unixtime_to_datetime, unix_now, output_handler
from TIPCommon import (
    extract_connector_param,
    siemplify_fetch_timestamp,
    validate_timestamp,
    string_to_multi_value,
    read_content,
    WHITELIST_FILTER,
    BLACKLIST_FILTER,
    TIMEOUT_THRESHOLD,
    NUM_OF_MILLI_IN_SEC
)
from constants import (
    QRADAR_OFFENCES_CONNECTOR_SCRIPT_NAME,
    DEFAULT_DOMAIN,
    RULE_ID_NAME_MAPPING_FILE,
    RULE_ID_NAME_MAPPING_DB_KEY,
    OFFENSES_CONNECTOR_NAME
)
from UtilsManager import load_offense_events, save_offense_events, create_rule_mapping

# CONSTANTS
from exceptions import QRadarConnectorValidationException, QRadarCustomFieldValidation, QRadarInvalidRuleException

ALERT_REQUIRED_FIELDS = ("custom_alert_name", "offense_description")
DEFAULT_MAX_DAYS_BACKWARDS = 1
DEFAULT_TOTAL_LIMIT_OF_EVENTS_PER_OFFENSE = 100
MAX_EVENTS_PER_ALERT = 100
DEFAULT_CONNECTOR_EVENTS_PAGE_SIZE = 100
DEFAULT_MAX_OFFENSES_FOR_CYCLE = 10
DEFAULT_OFFENSES_PADDING_PERIOD = 60
EVENTS_PADDING_PERIOD = 1
STOPPED_TIMER = -1
FAILED_TO_FETCH_EVENTS = "Cannot Fetch Events for the Offense"
ONE_MINUTE_UNIX_TIMESTAMP = 60_000


class QradarOffensesConnector(BaseConnector):
    def __init__(self):
        """
        Create an instance of the connector
        """
        self.common = None

        BaseConnector.__init__(self, QRADAR_OFFENCES_CONNECTOR_SCRIPT_NAME)
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
            self.logger.error("Connector requires Qradar API version 10.1 or higher.")
            raise Exception("Connector requires Qradar API version 10.1 or higher.")

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
            print_value=True,
            default_value=DEFAULT_CONNECTOR_EVENTS_PAGE_SIZE
        )
        self.validate_positive_integer_params(self.params.events_page_size, 'Connector Events Page Size',
                                              can_be_zero=False)

        self.params.offenses_limit_per_cycle = extract_connector_param(
            self.siemplify,
            param_name="Max Offenses per Cycle",
            is_mandatory=True,
            input_type=int,
            print_value=True,
            default_value=DEFAULT_MAX_OFFENSES_FOR_CYCLE
        )
        self.validate_positive_integer_params(self.params.offenses_limit_per_cycle, 'Max Offenses per Cycle',
                                              can_be_zero=False)

        self.params.offenses_padding_period = extract_connector_param(
            self.siemplify,
            param_name="Offenses Padding Period",
            is_mandatory=True,
            input_type=int,
            print_value=True,
            default_value=DEFAULT_OFFENSES_PADDING_PERIOD
        )
        self.validate_positive_integer_params(self.params.offenses_padding_period, 'Offenses Padding Period',
                                              can_be_zero=False)

        self.params.events_padding_period = extract_connector_param(
            self.siemplify,
            param_name="Events Padding Period",
            is_mandatory=True,
            input_type=int,
            print_value=True,
            default_value=EVENTS_PADDING_PERIOD
        )
        self.validate_positive_integer_params(self.params.events_padding_period, 'Events Padding Period',
                                              can_be_zero=False)

        self.params.events_limit_per_rule = extract_connector_param(
            self.siemplify,
            param_name="Events Limit per Qradar Offence Rule",
            is_mandatory=False,
            input_type=int,
            print_value=True
        )
        self.validate_positive_integer_params(self.params.events_limit_per_rule, 'Events Limit per Qradar Offence Rule',
                                              can_be_zero=False)

        self.params.max_days_backwards = extract_connector_param(
            self.siemplify,
            param_name="Max Days Backwards",
            is_mandatory=False,
            input_type=int,
            default_value=DEFAULT_MAX_DAYS_BACKWARDS,
            print_value=True
        )
        self.validate_positive_integer_params(self.params.max_days_backwards, 'Max Days Backwards',
                                              can_be_zero=False)

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

        self.params.domain_filter = extract_connector_param(
            self.siemplify,
            param_name="Domain Filter",
            is_mandatory=False,
            print_value=True
        )
        self.params.domain_filter_list = list(set(string_to_multi_value(self.params.domain_filter)))

        self.params.magnitude_filter = extract_connector_param(
            self.siemplify,
            param_name="Magnitude Filter",
            is_mandatory=False,
            input_type=int,
            print_value=True
        )
        self.validate_positive_integer_params(self.params.magnitude_filter, 'Magnitude Filter',
                                              can_be_zero=True)

        self.params.total_limit_of_events_per_offense = extract_connector_param(
            self.siemplify,
            param_name="Total limit of events per offense",
            is_mandatory=True,
            input_type=int,
            default_value=DEFAULT_TOTAL_LIMIT_OF_EVENTS_PER_OFFENSE,
            print_value=True
        )
        self.validate_positive_integer_params(self.params.total_limit_of_events_per_offense,
                                              'Total limit of events per offense',
                                              can_be_zero=True)

        self.params.whitelist_as_blacklist = extract_connector_param(
            self.siemplify,
            param_name="Use whitelist as a blacklist",
            print_value=True,
            is_mandatory=True,
            default_value=False,
            input_type=bool
        )

        self.params.disable_overflow = extract_connector_param(
            self.siemplify,
            param_name="Disable Overflow",
            print_value=True,
            is_mandatory=True,
            default_value=False,
            input_type=bool
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

        self.params.alert_name_field_name = extract_connector_param(
            self.siemplify,
            param_name="What Value to use for the Name Field of Siemplify Alert?",
            print_value=True
        )

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

        self.params.whitelist_filter_type = BLACKLIST_FILTER if self.params.whitelist_as_blacklist else WHITELIST_FILTER

        self.params.create_empty_cases = False

        self.validate_events_limit_per_rule()
        self.validate_alert_name_field_name()

    def load_rule_names_mappings(self):
        """
        Load rule names to ID mapping from file (or generate new mapping if needed)
        :return: {dict} The rule names mapping, in the following format:
        {
          "rules_id_name_mapping": {
            {
              "latest_rule_mapping_hashsum": "0A65C62595A803AF6A07AD9EC5D88D2921795387",
              "is_whitelist_as_blacklist": true,
              "last_update_timestamp": unixtime
            },
            {
            "mapping":
                {
                 "100205": "Destination Network Weight is Low",
                 "100211": "Source Network Weight is Low",
                 "100209": "Context Is Local to QRADAR _ DONT USE"
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
                calculate_hash=self.calculate_rule_mapping_hash(),
                rules=self.manager.list_rules(),
                connector_name=OFFENSES_CONNECTOR_NAME,
                logger=self.logger
            )
        else:
            try:
                mapping_expired = (
                    unix_now() - current_mapping.get("rules_id_name_mapping", {}).get("last_update_timestamp") >
                    self.params.qradar_offense_rules_resync_timer * ONE_MINUTE_UNIX_TIMESTAMP
                )
                if self.is_rule_mapping_changed(current_mapping.get("rules_id_name_mapping", {})
                                                         .get("latest_whitelist_hashsum")):
                    self.logger.info('Whitelist has changed. Creating new rule names mapping.')
                    current_mapping = create_rule_mapping(
                        siemplify=self.siemplify,
                        is_whitelist_as_blacklist=self.is_whitelist_as_blacklist(),
                        calculate_hash=self.calculate_rule_mapping_hash(),
                        rules=self.manager.list_rules(),
                        connector_name=OFFENSES_CONNECTOR_NAME,
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
                        calculate_hash=self.calculate_rule_mapping_hash(),
                        rules=self.manager.list_rules(),
                        connector_name=OFFENSES_CONNECTOR_NAME,
                        logger=self.logger
                    )

                elif mapping_expired:
                    self.logger.info(f"More then {self.params.qradar_offense_rules_resync_timer} minutes past since "
                                     f"the last update of the rule mapping. Creating new rule mapping")
                    current_mapping = create_rule_mapping(
                        siemplify=self.siemplify,
                        is_whitelist_as_blacklist=self.is_whitelist_as_blacklist(),
                        calculate_hash=self.calculate_rule_mapping_hash(),
                        rules=self.manager.list_rules(),
                        connector_name=OFFENSES_CONNECTOR_NAME,
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
                    calculate_hash=self.calculate_rule_mapping_hash(),
                    rules=self.manager.list_rules(),
                    connector_name=OFFENSES_CONNECTOR_NAME,
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
        if self.params.alert_name_field_name and self.params.alert_name_field_name not in ALERT_REQUIRED_FIELDS:
            self.logger.error('Valid values to use for the Name Field of Siemplify Alert are {}'
                              .format(' or '.join(ALERT_REQUIRED_FIELDS)))
            raise QRadarConnectorValidationException('Valid values to use for the Name Field of Siemplify Alert are {}'
                                                     .format(' or '.join(ALERT_REQUIRED_FIELDS)))

        return True

    def validate_events_limit_per_rule(self):
        if self.params.events_limit_per_rule is not None and self.params.events_limit_per_rule > self.params.total_limit_of_events_per_offense:
            self.logger.error('Provided value for the Events Limit per Qradar Offence Rule is '
                              'bigger than Total Limit of Events per Offense')
            raise QRadarConnectorValidationException('Provided value for the Events Limit per Qradar Offence Rule is '
                                                     'bigger than Total Limit of Events per Offense')

    def is_rule_mapping_changed(self, current_hash):
        """
        Check if the whitelist or blacklist has changed from previous runs by comparing its hash
        :param current_hash: {unicode} The currently saved hash of the whitelist or blacklist (saved in previous run)
        :return: {bool} True if changed, otherwise False.
        """
        return current_hash != self.calculate_rule_mapping_hash()

    def calculate_rule_mapping_hash(self):
        """
        Calculate the current rule mapping md5 hash
        :return: {unicode} The md5 of the rule mapping
        """
        return hashlib.md5(json.dumps(sorted(self.siemplify.whitelist)).encode()).hexdigest()

    def is_whitelist_as_blacklist(self):
        """
        Check if whitelist is used as blacklist
        :return: {bool} True if whitelist is used as blacklist, otherwise False
        """
        return self.params.whitelist_filter_type == BLACKLIST_FILTER

    def fetch_last_success_time(self):
        """
        Fetch the last success time of the connector.
        The last success time will be either the last updated time of the newest processed offense,
        ot (NOW - max_days_backwards param)
        :return:
        """
        try:
            # revert to siemplify.fetch_timestamp when SDK is ready
            saved_timestamp = siemplify_fetch_timestamp(siemplify=self.siemplify, datetime_format=True)
        except Exception as e:
            self.logger.error("An error as occurred while fetching saved timestamp. Resetting timestamp.")
            self.logger.exception(e)
            saved_timestamp = convert_unixtime_to_datetime(1)

        return validate_timestamp(
            saved_timestamp,
            offset_in_hours=self.params.max_days_backwards,
            offset_is_in_days=True
        )

    def pre_processing(self):
        """
        Perform some pre-processing in the connector
        """
        # Load rule names mapping
        self.load_rule_names_mappings()
        # Load already seen events hashes
        self.offense_events = load_offense_events(self.siemplify, self.params.offenses_padding_period)

        # If the offense padding period has changed or last timestamp is earlier than the padding period (means that
        # either the offenses were not updated in a long time, or the connector has stopped for a certain period) -
        if self.is_offense_padding_changed():
            self.logger.debug("Offense padding has changed.")

        # Add +1 to padding period to make sure that if a real timer has really exceeded, we will create an empty case
        # for it, and it won't be missed because of this condition.
        elif self.last_success_time_datetime < arrow.utcnow().shift(minutes=-self.params.offenses_padding_period + 1):
            self.logger.debug(
                "Last success time of connector is older than the offense padding period."
            )

    def is_whitelist_as_blacklist_changed(self, current_whitelist_as_blacklist_flag):
        """
        Check if "Use whitelist as a blacklist" parameter was changed from previous runs
        :param current_whitelist_as_blacklist_flag: {bool} The currently saved whitelist as blacklist boolean flag (saved in previous run)
        :return: {bool} True if changed, otherwise False.
        """
        return current_whitelist_as_blacklist_flag != self.params.whitelist_as_blacklist

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
            invalid_domains = self.filter_domains(all_domains, domain_ids)
            if invalid_domains:
                raise QRadarConnectorValidationException(
                    f"Following values for \"Domain Filter\" parameter were not found in QRadar: {', '.join(invalid_domains)}.")

        return self.manager.get_updated_offenses_from_time(
            timestamp_unix_time=convert_datetime_to_unix_time(fetch_time),
            domain_ids=domain_ids,
            magnitude_filter=self.params.magnitude_filter,
            connector_starting_time=self.connector_starting_time,
            python_process_timeout=self.params.python_process_timeout
        )

    def filter_domains(self, all_domains, domain_ids):
        """
        Filter domain to invalid domains and existing domains.
        :param all_domains: {dict} Json response from QRadar manager with domains data.
        :param domain_ids: {[str]} Empty list for the valid domain ids.
        :return: {[str]} List of invalid domain ids.
        """
        domains_name_to_id = {domain.name: domain.id for domain in all_domains}
        invalid_domains = []
        for domain in self.params.domain_filter_list:
            if domain == DEFAULT_DOMAIN:
                domain_ids.append(0)
            elif domain in domains_name_to_id:
                domain_ids.append(domains_name_to_id[domain])
            else:
                invalid_domains.append(domain)
        return invalid_domains

    def is_reached_total_limit_per_offense(self, fetched_offense):
        """
        Check if the offense reached the provided events limit
        :param fetched_offense: {datamodels.Offense} The offense to check
        :return: True if the offense reached the limit, else, False
        """
        events_counter = self.offense_events.get("offenses", {}).get(str(fetched_offense.id), {}).get(
            "events_counter")
        return events_counter >= self.params.total_limit_of_events_per_offense if events_counter is not None else False

    def process_alerts(self, fetched_offenses, is_test_run):
        """
        This method handles the processing of fetched offenses.
        For each offense, processes the offense and creates AlertInfo for each mapped rule in the offense that
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

                if self.is_reached_total_limit_per_offense(fetched_offense):
                    self.logger.info(
                        "The offense {} has reached the limit of events. Continue to the next fetched offense".format(
                            fetched_offense.id))
                    continue

                # Perform pre processing on the current alert
                self.alert_pre_processing(fetched_offense)

                current_mapped_rules = self.rule_names_mapping.get("rules_id_name_mapping", {}).get("mapping",
                                                                                                    {}).keys()

                if not self.is_passed_rule_mapped_filters(fetched_offense) and current_mapped_rules:
                    self.logger.info("Offense {} has no rules from the rules that mapped for the connector. Skipping."
                        .format(
                        self.alert_id_repr(fetched_offense) or "#{}".format(self.alert_id_repr(fetched_offense))))
                    continue

                alert_old_events_counter = self.get_offense_events_counter(fetched_offense)

                # Process a single alert - create an AlertInfo
                alert_infos, events = self.process_alert(fetched_offense, index)

                if alert_infos:
                    processed_offenses_count += len(alert_infos)

                for alert_info in alert_infos:
                    # Determine if the alert is an overflowed alert or not
                    is_overflow = (
                            not self.params.disable_overflow
                            and self.is_overflow_alert(alert_info, is_test_run)
                    )
                    if not is_overflow:
                        # The alert is not an overflow - add it to processed alert
                        processed_alerts.append(alert_info)
                        for event in events:
                            self.save_event_to_offense_events(fetched_offense, event)
                    else:
                        self.set_offense_events_counter(fetched_offense, alert_old_events_counter)

                    # Perform post processing on the current alert
                    self.alert_post_processing(fetched_offense, alert_info, is_overflow)

                    all_alerts.append(alert_info)

                self.logger.info('Finished processing offense {}.'
                    .format(
                    self.alert_id_repr(fetched_offense) or "#{}".format(self.alert_id_repr(fetched_offense))))

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
                    "Failed to process offense {}".format(
                        self.alert_id_repr(fetched_offense) or "#{}".format(self.alert_id_repr(fetched_offense)))
                )
                if isinstance(e, QRadarCustomFieldValidation):
                    raise Exception('Connector failed to run because provided Custom Fields caused Qradar AQL query '
                                    'validation error. Please make sure that the Custom Fields are provided without '
                                    'errors and exist in Qradar events table.')
                self.logger.exception(e)

                if is_test_run:
                    raise

        return all_alerts, processed_alerts

    def process_alert(self, offense, index):
        processed_alerts = []
        events = []
        total_events_count = 0
        current_mapped_rules = self.rule_names_mapping.get("rules_id_name_mapping", {}).get("mapping", {}).keys()

        self.logger.info(
            "Processing offense {}".format(self.alert_id_repr(offense) or "#{}".format(index))
        )

        offense_rules_names, offense_rules_ids = self.get_rule_ids_and_names(current_mapped_rules, offense)

        try:
            self.logger.info(
                "Fetching events of offense {}, for rules: {}\n ({})".format(
                    self.alert_id_repr(offense) or "#{}".format(index),
                    ", ".join(offense_rules_names),
                    ", ".join([str(rule_id) for rule_id in offense_rules_ids])
                )
            )

            if offense_rules_names:
                # Fetch the events of the offense for the current rule
                already_seen_events = self.get_already_seen_events_hashes(offense)

                if self.params.events_limit_per_rule is not None:
                    for rule_id in offense_rules_ids:
                        if self.is_approaching_timeout():
                            # Need to gracefully exit
                            break

                        if self.get_offense_rule_events_counter(offense.id,
                                                                rule_id) >= self.params.events_limit_per_rule:
                            self.logger.info(
                                "The number of events of the offense {} for rule '{}' has reached the limit. "
                                "Skipping.".format(offense.id, self.get_rule_name_by_id(rule_id)))
                            continue

                        if self.params.total_limit_of_events_per_offense - total_events_count <= 0:
                            self.logger.info("Reached the limit of events per offense {}".format(offense.id))
                            events = events[:self.params.total_limit_of_events_per_offense]
                            break

                        num_events_to_fetch = min(
                            self.params.total_limit_of_events_per_offense - self.get_offense_events_counter(
                                offense.id),
                            MAX_EVENTS_PER_ALERT,
                            self.params.events_limit_per_rule - self.get_offense_rule_events_counter(
                                offense.id, rule_id) if self.params.events_limit_per_rule else
                            MAX_EVENTS_PER_ALERT)

                        if num_events_to_fetch <= 0:
                            continue

                        try:
                            rule_events = self.get_events_for_rules(
                                offense=offense,
                                rule_ids=[rule_id],
                                limit=num_events_to_fetch,
                                existing_events_hashes=list(set(already_seen_events)),
                                total_limit_of_events_per_offense=self.params.total_limit_of_events_per_offense
                            )
                            self.set_rule_trigger_for_events(rule_events, rule_id)
                            events.extend(rule_events)

                            events_len = len(events)
                            total_events_count += len(rule_events)

                        except Exception as error:
                            self.logger.info("Failed to fetch events of offense {} for rule "
                                             "'{}'.".format(offense.id, self.get_rule_name_by_id(rule_id)))
                            if isinstance(error, QRadarCustomFieldValidation):
                                raise QRadarCustomFieldValidation()
                            self.logger.error(error)

                else:
                    num_events_to_fetch = min(
                        self.params.total_limit_of_events_per_offense - self.get_offense_events_counter(
                            offense.id),
                        MAX_EVENTS_PER_ALERT)

                    try:
                        all_rules_events = self.get_events_for_rules(
                            offense=offense,
                            rule_ids=offense_rules_ids,
                            limit=num_events_to_fetch,
                            existing_events_hashes=list(set(already_seen_events)),
                            total_limit_of_events_per_offense=self.params.total_limit_of_events_per_offense
                        )
                        events.extend(all_rules_events)

                        events_len = len(events)
                        total_events_count += len(all_rules_events)

                    except Exception as error:
                        self.logger.info("Failed to fetch events of offense {} for rules "
                                         "'{}'.".format(offense.id, offense_rules_names))
                        if isinstance(error, QRadarCustomFieldValidation):
                            raise QRadarCustomFieldValidation()
                        self.logger.error(error)

            else:
                self.logger.info("There are no rules for offense {} from the mapped rules. Skipping".format(offense.id))
                return

            if events:
                self.logger.info("Found {} events for rules {}\n ({})."
                                 .format(events_len, offense_rules_names,
                                         offense_rules_ids))
                self.logger.info("Creating an AlertInfo for offense {}\n"
                                 .format(offense.id))

                # Create an AlertInfo object for the offense and rule
                processed_alerts.append(self.create_alert_info(offense, events))

                # Stop the "failed to fetch events" timer for the offense

                self.logger.info(
                    "Finish processing events of offense {}, rules: {}\n ({})".format(
                        self.alert_id_repr(offense) or "#{}".format(index),
                        ", ".join(offense_rules_names),
                        ", ".join([str(rule_id) for rule_id in offense_rules_ids])
                    )
                )

        except Exception as e:
            self.logger.error("Failed fetching events of alert {} for rules {}."
                              .format(self.alert_id_repr(offense) or "#{}".format(index),
                                      ", ".join(offense_rules_names)))
            if isinstance(e, QRadarCustomFieldValidation):
                raise QRadarCustomFieldValidation()
            self.logger.exception(e)

        if not total_events_count:
            # No events were found for any of the whitelisted rules - starting timer.
            # If for a long period (current offense padding period), there will be no new events, we will
            self.logger.info('No events were found for offense {} for all mapped rules.'
                             .format(self.alert_id_repr(offense) or "#{}".format(index)))

        return processed_alerts, events

    def get_rule_ids_and_names(self, current_mapped_rules, offense):
        """
        Get the names and ids of the rules that triggered rules in the offense
        :param current_mapped_rules: {[str]} List rules mentioned in the current mapped rules
        :param offense:
        :return:
        """
        if current_mapped_rules:
            rules_ids = [rule_id for rule_id in offense.rule_ids if self.is_rule_id_mapped(rule_id)]
            offense_rules_names = [self.get_rule_name_by_id(rule_id) for rule_id in offense.rule_ids if
                                   self.is_rule_id_mapped(rule_id)]
        else:
            rules_ids = offense.rule_ids
            offense_rules_names = [self.get_rule_name_by_id(rule_id) for rule_id in offense.rule_ids]
        return offense_rules_names, rules_ids

    def set_rule_trigger_for_events(self, events, rule_id):
        """
        Set the rule that trigger the events for each event that was triggered by this rule
        :param events: [datamodels.event] List of Event data models
        :param rule_id: {int} Rule ID that trigger the events
        """
        for event in events:
            event.rule_triggered = rule_id

    def get_offense_rule_events_counter(self, offense_id, rule_id):
        """
        Get the number of events that was already processed for specific rule. If the rule or offense are not yet
        processed before, 0 will be returned.
        :param offense_id: {str} The ID of the offense to get the number of his events
        :param rule_id: {str} The ID of the rule to get the number of his events.
        :return: {int} The number of events of the provided rule in the offense.
        """
        return self.offense_events.get(
            "offenses", {}).get(str(offense_id), {}).get("rules_events_counter", {}).get(str(rule_id), 0)

    def get_offense_events_counter(self, offense_id):
        """
        Get the number of events that was already processed for specific event. If the offense is not yet processed
        before, The default events per offense value will be returned.
        :param offense_id: {str} The ID of the offense to get the number of his events
        :return: {int} The number of events of the provided offense.
        """
        return self.offense_events.get(
            "offenses", {}).get(str(offense_id), {}).get('events_counter', 0)

    def set_offense_events_counter(self, offense_id, alert_events_counter):
        """
        Set the number of events that was already processed for specific event. If the offense is not yet processed
        before, The default events per offense value will be returned.
        :param offense_id: {str} The ID of the offense to get the number of his events
        :param alert_events_counter: {int} The number of events of the offense.
        """
        offense_dict = self.offense_events.get("offenses", {}).get(str(offense_id), {})
        if offense_dict:
            offense_dict['events_counter'] = alert_events_counter

    def increase_events_counter_for_alert(self, offense_id):
        """
        Increase the events counter of an alert
        :param offense_id: {int} The ID of the offense to increase his events number
        """
        self.offense_events["offenses"][str(offense_id)]["events_counter"] += 1

    def is_approaching_timeout(self):
        """
        Check if a timeout is approaching.
        :return: {bool} True if timeout is close, False otherwise
        """
        processing_time_ms = unix_now() - self.connector_starting_time
        return processing_time_ms > self.params.python_process_timeout * NUM_OF_MILLI_IN_SEC * TIMEOUT_THRESHOLD

    def is_rule_id_mapped(self, rule_id):
        """
        Check if a given rule ID is mapped or not (by lookup in the rules mapping)
        :param rule_id: {int} The ID of the rule
        :return: {bool} True if mapped, False otherwise.
        """
        return str(rule_id) in list(self.rule_names_mapping.get("rules_id_name_mapping", {}).get("mapping", {}).keys())

    def get_rule_name_by_id(self, rule_id):
        """
        Get rule name by the rule ID
        :param rule_id: {int} The rule ID
        :return: {unicode} The rule name
        """
        self.load_rule_names_mappings()

        rule_name = self.rule_names_mapping.get("rules_id_name_mapping", {}).get("mapping", {}).get(str(rule_id))
        if not rule_name:
            self.logger.debug(f"Rule with id {rule_id} doesn't exist in Rule Mapping")

        return rule_name

    def get_events_for_rules(self, offense, rule_ids, limit=None, existing_events_hashes=[],
                             total_limit_of_events_per_offense=None):
        """
        Get events for an offense and a specific rule
        :param offense: {Offense} The offense to fetch events for
        :param rule_ids: {int} The rule ids to fetch events for
        :param limit: {int} Max amount of events to fetch
        :param existing_events_hashes: {[]} List of already seen events hashes
        :param total_limit_of_events_per_offense: {[]} List of already seen events hashes
        :return: {[Event]} List of events
        """
        return self.manager.get_events_by_offense_id(
            offense_id=offense.id,
            log_source_ids=[str(log_source_id) for log_source_id in offense.log_source_ids],
            rules_ids=[str(rule_id) for rule_id in rule_ids],
            custom_fields=self.params.custom_fields,
            events_period_padding=self.params.events_padding_period,
            limit=limit,
            existing_events_hashes=existing_events_hashes,
            page_size=self.params.events_page_size,
            total_limit_of_events_per_offense=total_limit_of_events_per_offense
        )

    def get_already_seen_events_hashes(self, offense):
        """
        Get the already seen events hashes for a given offense and rule id
        :param offense: {Offense} The offense to get the hashes for
        :param rule_id: {int} The rule id to get the events for
        :return: {[unicode]} List of already seen hashes
        """
        return self.offense_events["offenses"].get(str(offense.id), {}).get("events", [])

    def save_event_to_offense_events(self, offense, event):
        """
        Save an event to the offense_events.json file (mark event as already seen to avoid duplicates)
        :param offense: {Offense} The offense of the event
        :param rule_ids: {int} The ID of the rules that the event triggered
        :param event: {Event} The event to save
        """
        event_hash = event.as_hash()
        offense_id = str(offense.id)

        if offense_id not in list(self.offense_events["offenses"].keys()):
            # Offense was never in the offense events file. Need to create new record
            self.logger.debug(f"Offense {offense_id} is new for offenses file, creating an entry.")
            self.offense_events["offenses"][offense_id] = {
                "last_update_time": offense.last_updated_time,
                "events_counter": 1,
                "events": {
                    event_hash:
                        {
                            "timestamp": unix_now()
                        }
                },
                "rules_events_counter": {
                    str(event.rule_triggered): 0
                }
            }
        elif event_hash not in self.offense_events["offenses"][offense_id]["events"]:
            # Event is seen for the first time for the offense
            self.logger.debug(f"Event with hash {event_hash} is new for offense {offense_id}")
            self.offense_events["offenses"][offense_id]["events"][event_hash] = {
                "timestamp": unix_now()
            }

            self.offense_events["offenses"][offense_id]["events_counter"] += 1
            # Update the last_update_time of the offense
            self.offense_events["offenses"][offense_id]["last_update_time"] = offense.last_updated_time

        if self.params.events_limit_per_rule is not None:
            if str(event.rule_triggered) not in self.offense_events["offenses"][offense_id]["rules_events_counter"]:
                #  Rule triggered event for the current offense for the first time
                self.offense_events["offenses"][offense_id]["rules_events_counter"][str(event.rule_triggered)] = 1
            else:
                self.offense_events["offenses"][offense_id]["rules_events_counter"][str(event.rule_triggered)] += 1

            self.logger.debug(f'Events limit per rule is set, increasing the count of events for offense {offense_id}, '
                              f'new value is {self.offense_events["offenses"][offense_id]["rules_events_counter"][str(event.rule_triggered)]}')

    def create_alert_info(self, offense, events):
        """
        Create an AlertInfo object from a single alert and its activities
        :param offense: {Offense} An offense instance
        :param events: [Event] A list of the events objects related to the offense
        :return: {AlertInfo} The created alert info object
        """
        alert_info = AlertInfo()

        # Set the times of the AlertInfo based on the oldest and newest events in it
        events = sorted(events, key=lambda item: item.start_time or 1)
        alert_info.start_time = int(events[0].start_time or 1)
        alert_info.end_time = int(events[-1].end_time or 1)

        alert_info.ticket_id = "{offense_id}".format(offense_id=offense.id)
        alert_info.display_id = "{0}_{1}".format(alert_info.ticket_id, uuid.uuid4())
        alert_info.name = "Qradar offense {0}.\n{1}".format(offense.id,
                                                            offense.description) if \
            self.params.alert_name_field_name and self.params.alert_name_field_name == "custom_alert_name" else \
            offense.description
        alert_info.description = "{0}".format(offense.description)
        alert_info.device_vendor = self.common.get_category_human_readable_value(events[0].category if events else None)
        alert_info.device_product = events[0].device_product if events else "Error Getting Device Product"
        alert_info.priority = offense.priority
        alert_info.rule_generator = offense.description
        alert_info.environment = self.environment_common.get_environment(offense.as_extension())
        alert_info.source_grouping_identifier = offense.id
        alert_info.extensions.update(offense.as_extension())
        alert_info.extensions.update({"offense_id": offense.id})

        # Flat events data.
        try:
            alert_info.events = [event.as_event() for event in events]
        except Exception as e:
            self.logger.error("Unable to flatten events: {}".format(e))
            self.logger.exception(e)
            alert_info.events = []

        return alert_info

    def is_offense_padding_changed(self):
        """
        Check if Offense Padding Period param has changed since previous run
        :return: {bool} True if changed, False otherwise
        """
        if not self.offense_events:
            self.offense_events = load_offense_events(self.siemplify, self.params.offenses_padding_period)

        return self.params.offenses_padding_period != int(self.offense_events["last_offense_padding_period"])

    def is_passed_rule_mapped_filters(self, offense):
        """
        Check if the offense is whitelisted or blacklisted if whitelist is used as blacklist. An offense will be
        considered whitelisted if it is triggered by at least one whitelisted rule
        :param offense: {Offense} The offense
        :return: {bool} True if whitelisted, False otherwise
        """
        self.logger.info(
            "Offense {} rules: {}".format(offense.id, ", ".join([str(rule_id) for rule_id in offense.rule_ids]))
        )

        for rule_id in offense.rule_ids:
            if self.is_rule_id_mapped(rule_id):
                return True

        return False

    def filter_old_offense_events(self):
        """
        Filter old events hashes from the offense events to prevent the file from getting too big
        :return: {dict} Filtered offense events dict
        """
        filtered_offense_events = copy.deepcopy(self.offense_events)

        # Calculate the time limit beyond which an event hash will be considered old
        # The limit is equal to NOW - 2 * max(events_padding_period, max_days_backwards) to guarantee that a needed hash
        # won't be deleted too soon
        time_limit = arrow.utcnow().shift(
            days=-max(self.params.events_padding_period, self.params.max_days_backwards)).timestamp * 1000

        for offense_id in map(str, self.offense_events["offenses"].keys()):
            for event_hash, event_info in self.offense_events["offenses"][offense_id]["events"].items():
                if event_info.get("timestamp", 1) < time_limit:
                    del filtered_offense_events["offenses"][offense_id]["events"][event_hash]

        return filtered_offense_events

    def post_processing(self):
        """
        Perform some post-processing in the connector
        """
        # Save the updated events hashes to the offense events file
        self.save_filtered_offense_events()

    def alert_id_repr(self, offense):
        """
        Get the alert's ID representation (in this case - the ID of the offense)
        :param offense: {Offense} The offense
        :return: {int} The offense ID
        """
        return offense.id

    def validate_positive_integer_params(self, input_param, name: str, can_be_zero: bool):
        if input_param is not None:
            if not can_be_zero and input_param == 0:
                raise QRadarConnectorValidationException("'{}' must be a number bigger than 0".format(name))
            elif input_param < 0:
                raise QRadarConnectorValidationException("'{}' must be a number bigger or equal to 0".format(name))

    def save_filtered_offense_events(self):
        """
        Save the offense events file
        """
        # Before writing the new events - filter the old events hashes
        self.logger.info("Filtering old events hashes")
        self.offense_events = self.filter_old_offense_events()
        # Update the last_offense_padding_period to the current's run offense padding period
        self.offense_events["last_offense_padding_period"] = self.params.offenses_padding_period
        # Saving events to db\file dynamically
        save_offense_events(self.siemplify, self.params.offenses_padding_period, self.offense_events)

@output_handler
def main():
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    connector = QradarOffensesConnector()
    connector.run(is_test_run, process_single_alert_on_test=False)


if __name__ == '__main__':
    main()
