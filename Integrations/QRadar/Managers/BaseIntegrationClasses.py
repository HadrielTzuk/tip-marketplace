import datetime
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyUtils import unix_now, utc_now
from EnvironmentCommon import GetEnvironmentCommonFactory
from TIPCommon import (
    extract_connector_param,
    save_timestamp,
    siemplify_fetch_timestamp,
    is_overflowed,
    validate_timestamp
   )


class QRadarLoggerWrapper:
    def __init__(self, logger, debug_logging: bool = True):
        self.debug_logging = debug_logging
        self.logger = logger

    def info(self, message, *args, **kwargs):
        return self.logger.info(message, *args, **kwargs)

    def warn(self, message, *args, **kwargs):
        return self.logger.warn(message, *args, **kwargs)

    def error(self, message, *args, **kwargs):
        return self.logger.error(message, *args, **kwargs)

    def exception(self, message, *args, **kwargs):
        return self.logger.exception(message, *args, **kwargs)

    def debug(self, message: str, *args, **kwargs):
        if self.debug_logging:
            return self.logger.info(message, *args, **kwargs)


class Params(object):
    def __init__(self):
        self._params = {}

    def __get__(self, ins, type):
        return self._params.get(ins)

    def __set__(self, ins, value):
        self._params[ins] = value


class BaseConnector(object):
    MAP_FILE = "map.json"
    DEFAULT_OFFSET_TIME_HOURS = 24

    def __init__(self, script_name):
        """
        Base constructor. It should trigger load of entire integration configuration
        and configuration specific to the current action.
        """
        self.siemplify = SiemplifyConnectorExecution()
        self.siemplify.script_name = script_name
        self.logger = self.siemplify.LOGGER
        self.params = Params()
        self.identifier = self.siemplify.context.connector_info.identifier
        self.connector_starting_time = unix_now()
        self.logger.info("================= Main - Param Init =================")
        self.load_connector_configuration()
        self.set_connector_logger()
        self.load_common_classes()
        self.processed_offenses = []

    def set_connector_logger(self):
        self.logger = QRadarLoggerWrapper(self.logger)

    def load_integration_configuration(self):
        pass

    def load_manager(self):
        pass

    def load_common_classes(self):
        pass

    def load_connector_configuration(self):
        """
        This method loads connector configuration that must be in all connectors.
        To load additional per-connector configuration, override this method and call super()
        """
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
            self.logger.info("***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******")

        self.logger.info("------------------- Main - Started -------------------")

        try:
            self.logger.info("Loading managers")
            self.manager = self.load_manager()

            self.logger.info("Loading EnvironmentCommon")
            self.environment_common = GetEnvironmentCommonFactory.create_environment_manager(
                self.siemplify,
                self.params.environment_field_name,
                self.params.environment_regex
            )
            self.logger.info("Fetching last timestamp")
            self.last_success_time_datetime = self.fetch_last_success_time()
            self.logger.info("Last timestamp: {}".format(self.last_success_time_datetime.isoformat()))

            self.logger.info("Fetching alerts to process")
            self.fetched_alerts = self.get_alerts_to_process()

            self.logger.info("Collected {} alerts for processing.".format(len(self.fetched_alerts)))

            self.logger.info("Starting connector pre-processing")
            self.pre_processing()
            self.logger.info("Finished connector pre-processing")

            if is_test_run and process_single_alert_on_test:
                self.logger.info("This is a TEST run. Only 1 alert will be processed.")
                self.fetched_alerts = self.fetched_alerts[:1]

            self.logger.info("Processing alerts")
            self.all_alerts, self.processed_alerts = self.process_alerts(self.fetched_alerts, is_test_run)

            if not is_test_run:
                if self.processed_alerts:
                    self.logger.info("Starting connector post-processing")
                    self.post_processing()
                    self.logger.info("Finished connector post-processing")

                if self.processed_offenses:
                    self.logger.info("Saving timestamp")
                    self.self_save_timestamp()

            self.logger.info("Created total of {} cases".format(len(self.processed_alerts)))
            self.logger.info("------------------- Main - Finished -------------------")
            self.siemplify.return_package(self.processed_alerts, {}, [])

        except Exception as e:
            self.logger.error("General error occurred while running {}".format(self.siemplify.script_name))
            self.logger.exception(e)

            if is_test_run:
                raise

    def fetch_last_success_time(self):
        return validate_timestamp(
            # should replace with siemplify.fetch_timestamp after SDK changes are ready
            siemplify_fetch_timestamp(self.siemplify, datetime_format=True),
            offset_in_hours=self.params.first_time_run_offset_in_hours
        )

    def self_save_timestamp(self):
        """
        This method handles the implementation of connector timestamp saving.
        By default, the connector will sort the processed offenses objects based on their last_updated_time, and will
        set the last_updated_time as the new timestamp
        :return: {bool} is saved
        """
        return save_timestamp(self.siemplify, alerts=self.processed_offenses, timestamp_key='last_updated_time')

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
        :return: {[]} List of the events of the alert (usually either a list of event data model instances, or
        the alert's raw data, flattened)
        """
        return []

    def process_alert(self, fetched_alert, index):
        """
        This method handles the processing of a single alert.
        This method fetches the events of the alerts and creates an AlertInfo out of the alert
        :param fetched_alert: The fetched alert (supposed to be a data model instance of the alert)
        :param index: {int} The index of the alert within all the fetched alerts in the current connector cycle
        :return: {AlertInfo} The created AlertInfo for the alert
        """
        self.logger.info(
            "Processing alert {}".format(self.alert_id_repr(fetched_alert) or "#{}".format(index))
        )

        try:
            self.logger.info(
                "Fetching events of alert {}".format(self.alert_id_repr(fetched_alert) or "#{}".format(index))
            )

            # Fetch the events of the alert
            events = self.get_events(fetched_alert)
            self.logger.info("Found {} events".format(len(events)))

        except Exception as e:
            self.logger.error(
                "Failed fetching events of alert {}. "
                "Alert will be processed with no events.".format(
                    self.alert_id_repr(fetched_alert) or "#{}".format(index)
                )
            )
            self.logger.exception(e)
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
                    self.logger.info(
                        "Alert {} is not whitelisted. Skipping.".format(
                            self.alert_id_repr(fetched_alert) or "#{}".format(index)
                        )
                    )
                    continue

                # Process a single alert - create an AlertInfo
                alert_info = self.process_alert(fetched_alert, index)

                # Determine if the alert is an overflowed alert or not
                is_overflow = self.is_overflow_alert(alert_info, is_test_run)

                if not is_overflow:
                    # The alert is not an overflow - add it to processed alert
                    processed_alerts.append(alert_info)

                    self.logger.info(
                        'Finished processing alert {}.'.format(
                            self.alert_id_repr(fetched_alert) or "#{}".format(index)
                        )
                    )

                # Perform post processing on the current alert
                self.alert_post_processing(fetched_alert, alert_info, is_overflow)

                all_alerts.append(alert_info)

            except Exception as e:
                self.logger.error(
                    "Failed to process alert {}".format(self.alert_id_repr(fetched_alert) or "#{}".format(index))
                )
                self.logger.exception(e)

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
        overflowed = is_overflowed(self.siemplify, alert_info, is_test_run)
        if overflowed:
            self.logger.info(
                    "{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping."
                        .format(alert_name=str(alert_info.rule_generator),
                                alert_identifier=str(alert_info.ticket_id),
                                environment=str(alert_info.environment),
                                product=str(alert_info.device_product))
                )
        return overflowed

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
