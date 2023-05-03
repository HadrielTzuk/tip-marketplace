from utils import get_last_success_time, save_timestamp_by_timestamp_file, UNIX_FORMAT, \
    get_formatted_date_from_timestamp, get_filters_by_alert_type, pass_filters
from consts import ALERT_TYPES, ALERT_TYPE_NAMES, UNIFIED_CONNECTOR_DEFAULT_MAX_LIMIT
from SiemplifyConnectorsDataModel import AlertInfo
from TIPCommon import read_ids, write_ids, filter_old_alerts


IDS_FILE_NAME = "RULE_ids.json"
IDS_DB_KEY = "RULE_ids"
TIMESTAMP_FILE_NAME = "RULE_timestamp.stmp"
TIMESTAMP_DB_KEY = "RULE_timestamp"
TIMESTAMP_KEY = "timestamp"
STORED_IDS_LIMIT = 1000
TIMEOUT_THRESHOLD = 0.8


class RuleAlert:
    def __init__(self, siemplify, manager, python_process_timeout, connector_starting_time):
        self.siemplify = siemplify
        self.manager = manager
        self.python_process_timeout = python_process_timeout
        self.connector_starting_time = connector_starting_time

    def read_ids(self):
        """
        Read ids from ids file
        :return: {list} list of ids
        """
        existing_ids = read_ids(self.siemplify, ids_file_name=IDS_FILE_NAME, db_key=IDS_DB_KEY,
                                default_value_to_return=[])
        self.siemplify.LOGGER.info(f"Successfully loaded {len(existing_ids)} existing "
                                   f"{ALERT_TYPE_NAMES.get(ALERT_TYPES.get('rule'))} ids")
        return existing_ids

    def get_alerts(self, existing_ids, fetch_limit, hours_backwards, fallback_severity=None, padding_period=None):
        """
        Get alerts
        :param existing_ids: {list} list of existing ids
        :param fetch_limit: {int} limit for results
        :param hours_backwards: {int} amount of hours from where to fetch alerts
        :param fallback_severity: {str} fallback severity
        :param padding_period: {int} padding period for alerts in hours
        :return: {list} list of Detection objects
        """
        last_success_timestamp = get_last_success_time(
            siemplify=self.siemplify,
            offset_with_metric={"hours": hours_backwards},
            time_format=UNIX_FORMAT,
            timestamp_file_name=TIMESTAMP_FILE_NAME,
            timestamp_db_key=TIMESTAMP_DB_KEY
        )

        alerts = self.manager.stream_detection_alerts_in_retry_loop(
            get_formatted_date_from_timestamp(last_success_timestamp),
            fetch_limit,
            self.python_process_timeout,
            self.connector_starting_time,
            TIMEOUT_THRESHOLD,
            fallback_severity=fallback_severity
        )

        alerts = sorted(alerts, key=lambda alert: int(getattr(alert, TIMESTAMP_KEY)))
        filtered_alerts = filter_old_alerts(self.siemplify, alerts, existing_ids, "id")
        self.siemplify.LOGGER.info(f"Fetched {len(filtered_alerts)} {ALERT_TYPE_NAMES.get(ALERT_TYPES.get('rule'))} "
                                   f"alerts")
        return filtered_alerts

    def pass_filters(self, alert):
        filters = get_filters_by_alert_type(self.siemplify.LOGGER, self.siemplify.whitelist, ALERT_TYPES.get("rule"))
        return pass_filters(self.siemplify.LOGGER, alert, filters)

    def write_ids(self, existing_ids):
        """
        Write ids to ids file
        :param existing_ids: {list} list of existing ids
        :return: {void}
        """
        write_ids(self.siemplify, existing_ids, ids_file_name=IDS_FILE_NAME, db_key=IDS_DB_KEY, default_value_to_set=[],
                  stored_ids_limit=STORED_IDS_LIMIT)

    def save_timestamp(self, alerts):
        """
        Save last timestamp for given alerts
        :param alerts: {list} list of Detection objects
        :return: {void}
        """
        save_timestamp_by_timestamp_file(self.siemplify, alerts, TIMESTAMP_KEY, timestamp_file_name=TIMESTAMP_FILE_NAME,
                                         timestamp_db_key=TIMESTAMP_DB_KEY)

    @staticmethod
    def get_alert_info(alert, environment_common, device_product_field):
        """
        Get alert info
        :param alert: {Detection} Detection object
        :param environment_common: {EnvironmentHandle} environment common object for fetching the environment
        :param device_product_field: {str} key to use for device product extraction
        :return: {AlertInfo} AlertInfo object
        """
        return alert.as_unified_alert_info(
            AlertInfo(),
            environment_common,
            device_product_field
        )
