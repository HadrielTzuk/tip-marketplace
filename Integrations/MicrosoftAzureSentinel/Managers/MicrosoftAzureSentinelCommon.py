from SiemplifyUtils import unix_now
import json
from dateutil.parser import parse
from exceptions import TimeoutIsApproachingError
from TIPCommon import validate_existence, read_content, write_content

BACKLOG_IDS_FILE = "backlog_ids.json"
PROCESSED_INCIDENTS_LIST_FILE = "processed_incidents_list.json"
NEXT_PAGE_ALERT_LINK_FILE = "next_page_alert_link.json"

BACKLOG_IDS_DB_KEY = "backlog_ids"
PROCESSED_INCIDENTS_LIST_DB_KEY = "processed_incidents_list"
NEXT_PAGE_ALERT_LINK_DB_KEY = "next_page_alert_link"

IDS_HOURS_LIMIT = 24
TIMEOUT_THRESHOLD = 0.9
NUM_OF_MILLI_IN_SEC = 1000


class MicrosoftAzureSentinelCommon(object):
    def __init__(self, siemplify_logger):
        self.siemplify_logger = siemplify_logger

    @staticmethod
    def is_approaching_timeout(connector_starting_time, python_process_timeout):
        """
        Check if a timeout is approaching.
        :param connector_starting_time: {int} Connector start time
        :param python_process_timeout: {int} The python process timeout
        :return: {bool} True if timeout is close, False otherwise
        """
        processing_time_ms = unix_now() - connector_starting_time
        return processing_time_ms > python_process_timeout * NUM_OF_MILLI_IN_SEC * TIMEOUT_THRESHOLD

    @staticmethod
    def raise_if_timeout(connector_starting_time, python_process_timeout):
        """
        Raise exception if timeout is approaching.
        :param connector_starting_time: {int} Connector start time
        :param python_process_timeout: {int} The python process timeout
        """
        if MicrosoftAzureSentinelCommon.is_approaching_timeout(connector_starting_time, python_process_timeout):
            raise TimeoutIsApproachingError('Timeout is approaching. Connector will gracefully exit')

    @staticmethod
    def filter_old_ids(alerts, existing_ids):
        """
        Filter ids that were already processed
        :param alerts: {list} The objects to filter
        :param existing_ids: {list} The ids to filter
        :return: {list} The filtered alerts
        """
        new_alerts = []

        for alert in alerts:
            if alert.name not in existing_ids.keys():
                new_alerts.append(alert)

        return new_alerts


def is_date(string, fuzzy=False):
    """
    Return whether the string can be interpreted as a date.

    :param string: str, string to check for date
    :param fuzzy: bool, ignore unknown tokens in string if True
    """
    try:
        parse(string, fuzzy=fuzzy)
        return True

    except ValueError:
        return False


def validate_backlog(siemplify):
    """
    Validate if backlog file is already exist, otherwise create it
    :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class.
    """
    validate_existence(BACKLOG_IDS_FILE, BACKLOG_IDS_DB_KEY, {}, siemplify)


def validate_alerts_next_page(siemplify):
    """
    Validate if alerts next page file is already exist, otherwise create it
    :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class.
    """
    validate_existence(NEXT_PAGE_ALERT_LINK_FILE, NEXT_PAGE_ALERT_LINK_DB_KEY, "", siemplify)


def validate_incidents_numbers(siemplify):
    """
    Validate incidents numbers file is already exist, otherwise create it
    :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class.
    """
    validate_existence(PROCESSED_INCIDENTS_LIST_FILE, PROCESSED_INCIDENTS_LIST_DB_KEY, [], siemplify)


def read_backlog_ids(siemplify):
    """
    Read this specific file content
    :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class.
    :return: the files content
    """
    backlog_ids = read_content(siemplify, BACKLOG_IDS_FILE, BACKLOG_IDS_DB_KEY, {})
    siemplify.LOGGER.info(f'Total alerts in backlog: {len(backlog_ids)}')
    return backlog_ids


def read_next_page_alerts(siemplify):
    """
    Read this specific file content
    :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class.
    :return: the files content
    """
    content = read_content(siemplify, NEXT_PAGE_ALERT_LINK_FILE, NEXT_PAGE_ALERT_LINK_DB_KEY, "")
    return json.loads(content) if content else None


def read_incidents_numbers(siemplify):
    """
    Read this specific file content
    :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class.
    :return: the files content
    """
    return read_content(siemplify, PROCESSED_INCIDENTS_LIST_FILE, PROCESSED_INCIDENTS_LIST_DB_KEY, [])


def write_backlog_ids(siemplify, data_to_write):
    """
    Write this specific file content
    :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class
    :param data_to_write: The content to write in the file.
    """
    siemplify.LOGGER.info(f'Total alerts in backlog: {len(data_to_write)}')
    write_content(siemplify, data_to_write, BACKLOG_IDS_FILE, BACKLOG_IDS_DB_KEY, {})


def write_next_page_alerts(siemplify, data_to_write):
    """
    Write this specific file content
    :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class
    :param data_to_write: The content to write in the file.
    """
    write_content(siemplify, data_to_write, NEXT_PAGE_ALERT_LINK_FILE, NEXT_PAGE_ALERT_LINK_DB_KEY, "")


def write_incidents_numbers(siemplify, data_to_write):
    """
    Write ids to the ids file
    :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class
    :param data_to_write: The content to write in the file.
    """
    write_content(siemplify, data_to_write, PROCESSED_INCIDENTS_LIST_FILE, PROCESSED_INCIDENTS_LIST_DB_KEY, [])
