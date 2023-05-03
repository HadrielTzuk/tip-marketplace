import datetime
import json
import logging
import os

import arrow
from EnvironmentCommon import EnvironmentHandle
from TIPCommon import extract_connector_param

from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyMock import SiemplifyConnectorMock
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, utc_now


class Base(object):
    IDS_FILE = "ids.json"

    def __init__(self, siemplify, script_name):
        self.siemplify = siemplify
        self.siemplify.script_name = script_name
        self.logger = self.siemplify.LOGGER._log
        self.params = Params()

    def load_integration_configuration(self):
        pass

    def load_manager(self):
        pass

    def load_common_classes(self):
        pass

    def log(self, msg, level=logging.INFO, include_traceback=False):
        if include_traceback:
            self.logger.log(level, msg, exc_info=1)
        else:
            self.logger.log(level, msg)

    @staticmethod
    def validate_timestamp(last_run_timestamp, offset_in_hours):
        """
        Validate timestamp in range
        :param last_run_timestamp: {datetime} last run timestamp
        :param offset_in_hours: The max offset allowed in hours
         offset: {datetime} last run timestamp
        :return: {datetime} if first run, return current time minus offset time, else return timestamp from file
        """
        current_time = utc_now()
        # Check if first run
        if current_time - last_run_timestamp > datetime.timedelta(hours=offset_in_hours):
            return current_time - datetime.timedelta(hours=offset_in_hours)
        else:
            return last_run_timestamp

    def validate_map_file(self, map_file_path):
        """
        Validate the existence of the environment mapping file
        :param map_file_path: {str} The path to the map file
        """
        try:
            if not os.path.exists(map_file_path):
                with open(map_file_path, 'w+') as map_file:
                    map_file.write(json.dumps(
                        {"Original environment name": "Desired environment name",
                         "Env1": "MyEnv1"}))
                    self.log(
                        "Mapping file was created at {}".format(map_file),
                        level=logging.INFO
                    )

        except Exception as e:
            self.log("Unable to create mapping file: {}".format(e), level=logging.ERROR)
            self.log(e, level=logging.ERROR, include_traceback=True)

    def read_ids(self, cast_keys_to_int=False, max_hours_backwards=24, ids_file_path=None):
        """
        Read existing (arleady seen) alert ids from the ids.json file
        :param cast_keys_to_int: {bool} Whether to case the ids to int or not
        :param max_hours_backwards: {int} Max amount of hours to keep ids in the file (to prevent it from getting too big)
        :param ids_file_path: {str} The path of the ids file.
        :return:{dict} A dict describing the already seen ids {id: the unixtime when it was first seen}
        """
        ids_file_path = os.path.join(self.siemplify.run_folder, ids_file_path or self.IDS_FILE)
        self.log("Fetching existing IDs from: {0}".format(ids_file_path), level=logging.INFO)

        try:
            if not os.path.exists(ids_file_path):
                self.log("Ids file doesn't exist at path {}".format(ids_file_path), level=logging.INFO)
                return {}

            with open(ids_file_path, 'r') as f:
                self.log("Reading existing ids from ids file", level=logging.INFO)
                existing_ids = json.loads(f.read())

                filtered_ids = {}
                # Insert IDs that did not passed time retention time limit.
                for alert_id, timestamp in existing_ids.items():
                    if timestamp > arrow.utcnow().shift(hours=-max_hours_backwards).timestamp * 1000:
                        filtered_ids[alert_id] = timestamp

                if cast_keys_to_int:
                    return {int(k): v for k, v in filtered_ids.items()}

                return filtered_ids

        except Exception as e:
            self.log("Unable to read ids file: {}".format(e), level=logging.ERROR)
            self.log(e, level=logging.ERROR, include_traceback=True)
            return {}

    def write_ids(self, ids, ids_file_path=None):
        """
        Write ids to the ids file
        :param ids_file_path: {str} The path of the ids file.
        :param ids: {dict} The ids to write to the file
        """
        try:
            ids_file_path = os.path.join(self.siemplify.run_folder, ids_file_path or self.IDS_FILE)
            self.log("Writing ids to file: {}".format(ids_file_path), level=logging.INFO)

            if not os.path.exists(os.path.dirname(ids_file_path)):
                self.log("Ids file doesn't exist at {}. Creating new file.".format(ids_file_path), level=logging.INFO)
                os.makedirs(os.path.dirname(ids_file_path))

            with open(ids_file_path, 'w') as f:
                try:
                    for chunk in json.JSONEncoder().iterencode(ids):
                        f.write(chunk)
                except:
                    # Move seeker to start of the file
                    f.seek(0)
                    # Empty the content of the file (the partially written content that was written before the exception)
                    f.truncate()
                    # Write an empty dict to the events data file
                    f.write("{}")
                    raise

        except Exception as e:
            self.log("Failed writing IDs to IDs file, ERROR: {0}".format(e), level=logging.ERROR)
            self.log(e, level=logging.ERROR, include_traceback=True)


class Params(object):
    def __init__(self):
        self._params = {}

    def __get__(self, ins, type):
        return self._params.get(ins)

    def __set__(self, ins, value):
        self._params[ins] = value


class BaseConnector(Base):
    MAP_FILE = "map.json"
    DEFAULT_OFFSET_TIME_HOURS = 24

    def __init__(self, script_name, test_mode=False, parameters={}, whitelist=[]):
        """
        Base constructor. It should trigger load of entire integration configuration
        and configuration specific to the current action.
        """
        if test_mode:
            super(BaseConnector, self).__init__(
                SiemplifyConnectorMock(
                    parameters=parameters,
                    whitelist=whitelist,
                    connector_name=script_name
                ),
                script_name
            )
        else:
            super(BaseConnector, self).__init__(SiemplifyConnectorExecution(), script_name)

        self.connector_starting_time = unix_now()
        self.log("================= Main - Param Init =================", level=logging.INFO)
        self.log("Loading connector configurations", level=logging.INFO)
        self.load_connector_configuration()
        self.log("Successfully loaded connector configuration", level=logging.INFO)

    def load_connector_configuration(self):
        """
        This method loads connector configuration that must be in all connectors.
        To load additional per-connector configuration, override this method and call super()
        """
        self.params.environment_field_name = extract_connector_param(
            self.siemplify,
            param_name="Environment Field Name",
            is_mandatory=False,
            input_type=str,
            print_value=True
        )

        self.params.environment_regex = extract_connector_param(
            self.siemplify,
            param_name="Environment Regex Pattern",
            is_mandatory=False,
            input_type=str,
            print_value=True
        )

        self.params.first_time_run_offset_in_hours = extract_connector_param(
            self.siemplify,
            param_name="Offset Time In Hours",
            is_mandatory=True,
            default_value=self.DEFAULT_OFFSET_TIME_HOURS,
            input_type=int,
            print_value=True
        )

    def run(self, is_test_run=False, process_single_alert_on_test=True):
        """
        This method runs a single cycle of the connector
        :param is_test_run: {bool} Whether this run is a test run of the connector or not
        :param process_single_alert_on_test: {bool} Whether to process only single alert in test run or not
        """
        if is_test_run:
            self.log("***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******",
                     level=logging.INFO)

        self.log("------------------- Main - Started -------------------", level=logging.INFO)

        try:
            map_file_path = os.path.join(self.siemplify.run_folder, self.MAP_FILE)
            self.log("Validating environments mapping file at: {}".format(map_file_path), level=logging.INFO)
            self.validate_map_file(map_file_path)

            self.log("Loading EnvironmentCommon", level=logging.INFO)
            self.environment_common = EnvironmentHandle(map_file_path, self.logger, self.params.environment_field_name,
                                                        self.params.environment_regex,
                                                        self.siemplify.context.connector_info.environment)

            self.log("Fetching last timestamp", level=logging.INFO)
            self.last_success_time_datetime = self.fetch_last_success_time()
            self.log("Last timestamp: {}".format(self.last_success_time_datetime.isoformat()), level=logging.INFO)

            self.log("Fetching alerts to process", level=logging.INFO)
            self.fetched_alerts = self.get_alerts_to_process()

            self.log("Collected {} alerts for processing.".format(len(self.fetched_alerts)), level=logging.INFO)

            self.log("Starting connector pre-processing", level=logging.INFO)
            self.pre_processing()
            self.log("Finished connector pre-processing", level=logging.INFO)

            if is_test_run and process_single_alert_on_test:
                self.log("This is a TEST run. Only 1 alert will be processed.", level=logging.INFO)
                self.fetched_alerts = self.fetched_alerts[:3]

            self.log("Processing alerts")
            self.all_alerts, self.processed_alerts = self.process_alerts(self.fetched_alerts, is_test_run)

            self.log("Starting connector post-processing", level=logging.INFO)
            self.post_processing()
            self.log("Finished connector post-processing", level=logging.INFO)

            if not is_test_run and self.all_alerts:
                self.log("Saving timestamp", level=logging.INFO)
                self.save_timestamp(self.all_alerts)

            self.log("Created total of {} cases".format(len(self.processed_alerts)), level=logging.INFO)
            self.log("------------------- Main - Finished -------------------", level=logging.INFO)
            self.siemplify.return_package(self.processed_alerts, {}, [])

        except Exception as e:
            self.log("General error occurred while running {}".format(self.siemplify.script_name), logging.ERROR)
            self.log(e, logging.ERROR, include_traceback=True)

            if is_test_run:
                raise

    def pass_watchlist_filter(self, alert):
        """
        Pass watchlist filter.
        :param alert: {datamodel.Alert} Alert to apply watchlist filter.
        :return: {bool} True if pass the watchlist filter.
        """
        if not alert.is_watchlist_type():
            return True

        if not self.params.watchlist_name_filter:
            return True
        is_pass = bool([watchlist_name for watchlist_name in alert.watchlists_names if watchlist_name
                        in self.params.watchlist_name_filter])
        if not is_pass:
            self.log("Alert with watchlist name(s) '{}' did not pass watchlist filter.".format(','.join(alert.watchlists_names)))
        return is_pass

    @staticmethod
    def string_to_multi_value(string_value, delimiter=','):
        """
        String to multi value.
        :param string_value: {str} String value to convert multi value.
        :param delimiter: {str} Delimiter to extract multi values from single value string.
        :return: {dict} fixed dictionary.
        """
        if not string_value:
            return []
        return [single_value.strip() for single_value in string_value.split(delimiter) if single_value.strip()]

    def fetch_last_success_time(self):
        return self.validate_timestamp(
            self.siemplify.fetch_timestamp(datetime_format=True),
            offset_in_hours=self.params.first_time_run_offset_in_hours
        )

    def save_timestamp(self, alerts):
        """
        This method handles the implementation of connector timestamp saving.
        By default, the connector will sort the AlertInfo objects based on their start_time, and will set the new
        timestamp as the start_time of the newest alert + 1ms
        :param alerts: {[AlertInfo]} The created AlertInfo objects
        """
        alerts = sorted(alerts, key=lambda alert: alert.start_time)
        self.log("Saved timestamp: {}".format(convert_unixtime_to_datetime(alerts[-1].start_time + 1).isoformat()),
                 level=logging.INFO)
        self.siemplify.save_timestamp(new_timestamp=alerts[-1].start_time + 1)

    def pre_processing(self):
        """
        Implement this method to perform some pre-processing in the connector.
        For example, this method could be used to sort the alerts based on their timestamp field before slicing up to the
        max alerts per cycle limit. Or this could be used to filter out alerts that are not in the whitelist.
        Also this method could be used to filter out alerts using the ids.json file.
        The fetched alert can be accessed by calling self.fetched_alerts
        """
        pass

    def post_processing(self):
        """
        Implement this method to perform some post-processing in the connector.
        For example, this method could be used for adding a field to all the created processed AlertInfo objects,
        or updating the ids.json file with newly found alerts.
        """
        pass

    def alert_pre_processing(self, alert):
        """
        Implement this method to perform some pre processing on a specific alert. For example this could be used to
        check the alert against the whitelist, or to fetch additional info for the current alert/
        :param alert: One of the fetched alerts (supposed to be an alert data model instance)
        """
        pass

    def alert_post_processing(self, fetched_alert, alert_info, is_overflow):
        """
        Implement this method to perform some post processing on a specific alert. This method could be used to perform
        some logic based on the overflow status of the alert, or for example ot could be used to update the existing ids
        from ids.json
        :param fetched_alert: The fetched alert (supposed to be an alert data model instance)
        :param alert_info: {AlertInfo} The matching AlertInfo object created from the fetched alert
        :param is_overflow: {bool} The overflow status of the alert
        """
        pass

    def get_alerts_to_process(self):
        """
        This method handles the fetching of the alerts to process by the connector.
        This method should fetch the alerts using the manager, based on the last run timestamp.
        The last run timestamp can be accessed using self.last_success_time_datetime, and the manager using self.manager
        :return: {[]} The fetched alerts (supposed to be a list of the data model instanses of the found alerts)
        """
        return []

    def get_events(self, fetched_alert):
        """
        This method handles the fetching of the events for a specific event.
        :param fetched_alert: The fetched alert (supposed to be a data model instance of the alert)
        :param fetched_alert: The fetched alert (supposed to be a data model instance of the alert)
        :return: {[]} List of the events of the alert (usually either a list of event data model instances, or
        the alert's raw data, flattened)
        """
        return []

    def process_alert(self, fetched_alert, index, is_test_run=False):
        """
        This method handles the processing of a single alert.
        This method fetches the events of the alerts and creates an AlertInfo out of the alert
        :param fetched_alert: The fetched alert (supposed to be a data model instance of the alert)
        :param index: {int} The index of the alert within all the fetched alerts in the current connector cycle
        :return: {AlertInfo} The created AlertInfo for the alert
        """
        self.log(
            "Processing alert {}".format(self.alert_id_repr(fetched_alert) or "#{}".format(index)),
            level=logging.INFO
        )

        try:
            self.log(
                "Fetching events of alert {}".format(self.alert_id_repr(fetched_alert) or "#{}".format(index)),
                level=logging.INFO
            )

            # Fetch the events of the alert
            events = self.get_events(fetched_alert)
            self.log("Found {} events".format(len(events)))

        except Exception as e:
            self.log(
                "Failed fetching events of alert {}. "
                "Alert will be processed with no events.".format(
                    self.alert_id_repr(fetched_alert) or "#{}".format(index)
                ),
                level=logging.ERROR
            )
            self.log(e, level=logging.ERROR, include_traceback=True)
            events = []

        # Create an AlertInfo object for the alert
        return self.create_alert_info(fetched_alert, events)

    def is_whitelisted_alert(self, alert):
        return True

    def process_alerts(self, fetched_alerts, is_test_run):
        """
        This method handles the processing of fetched alerts.
        For each alert, this method does pre processing, processes the alert and creates AlertInfo for it, checks the
        alert's overflow status and performs some post processing.
        :param fetched_alerts: {[]} The fetched alerts (supposed to be a list of the data model instanses of the found alerts)
        :param is_test_run: {bool} Whether the current run of the connector is a test run or not
        :return: ([], []) All created AlertInfo objects, only the processed AlertInfo (non-overflowed)
        """
        all_alerts = []
        processed_alerts = []

        # In this template example, we create a random number of dummy alerts:
        for index, fetched_alert in enumerate(fetched_alerts):
            try:
                # Perform pre processing on the current alert
                self.alert_pre_processing(fetched_alert)

                if not self.is_whitelisted_alert(fetched_alert):
                    self.log(
                        "Alert {} is not whitelisted. Skipping.".format(
                            self.alert_id_repr(fetched_alert) or "#{}".format(index)
                        ),
                        level=logging.INFO
                    )
                    continue

                # Process a single alert - create an AlertInfo
                alert_info = self.process_alert(fetched_alert, index)

                # Determine if the alert is an overflowed alert or not
                is_overflow = self.is_overflow_alert(alert_info, is_test_run)

                if not is_overflow:
                    # The alert is not an overflow - add it to processed alert
                    processed_alerts.append(alert_info)

                    self.log(
                        'Finished processing alert {}.'.format(
                            self.alert_id_repr(fetched_alert) or "#{}".format(index)
                        ),
                        level=logging.INFO
                    )

                # Perform post processing on the current alert
                self.alert_post_processing(fetched_alert, alert_info, is_overflow)

                all_alerts.append(alert_info)

            except Exception as e:
                self.log(
                    "Failed to process alert {}".format(self.alert_id_repr(fetched_alert) or "#{}".format(index)),
                    level=logging.ERROR
                )
                self.log(e, level=logging.ERROR, include_traceback=True)

                if is_test_run:
                    raise

        return all_alerts, processed_alerts

    def is_overflow_alert(self, alert_info, is_test_run):
        """
        This method is used to determine if an alert if an overflow alert or not.
        By default, this method will use the built in Overflow mechanism of the SiemplifySDK.
        :param alert_info: {AlertInfo} The alert info to check
        :param is_test_run: {bool} Whether the current run of the connector is a test run or not
        :return: {bool} True if overflow, otherwise False.
        """
        is_overflowed = False

        try:
            is_overflowed = self.siemplify.is_overflowed_alert(
                environment=alert_info.environment,
                alert_identifier=alert_info.ticket_id,
                alert_name=alert_info.rule_generator,
                product=alert_info.device_product
            )

        except Exception as e:
            self.log(
                'Error validation connector overflow',
                level=logging.ERROR
            )
            self.log(e, level=logging.ERROR, include_traceback=True)

            if is_test_run:
                raise

        if is_overflowed:
            self.log(
                "{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping."
                    .format(alert_name=str(alert_info.rule_generator),
                            alert_identifier=str(alert_info.ticket_id),
                            environment=str(alert_info.environment),
                            product=str(alert_info.device_product)),
                level=logging.INFO
            )

        return is_overflowed

    @staticmethod
    def alert_id_repr(fetched_alert):
        """
        Implement this method to define the textual representation of your fetched alert's id (usually this will depend
        on the data model attribute matching the id field of the alert)
        :param fetched_alert: The fetched alert to return it's id (supposed to be an alert data model instance)
        :return: {unicode} The textual representation of the id of the alert
        """
        return None

    def create_alert_info(self, fetched_alert, events):
        """
        Implement this method to create an AlertInfo object out of a fetched alert and its events
        :param fetched_alert: The fetched alert to return it's id (supposed to be an alert data model instance)
        :param events: {[]} List of the fetched alert's events
        :return: {AlertInfo} The alert info created for the fetched alert
        """
        pass
