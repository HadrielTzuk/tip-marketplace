import os
import json
import arrow
from exceptions import SentinelOneV2AlreadyExistsError
from constants import FILTER_KEY_MAPPING, FILTER_STRATEGY_MAPPING


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


def get_entity_original_identifier(entity):
    """
    Helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get('OriginalIdentifier', entity.identifier)


def is_folder_path(path):
    """
    Helper function for getting path is for folder or for path
    :param path: path
    :return: {bool} true if path is for folder otherwise false
    """
    return path[-1] == '/'


# Move to TIPCommon
def read_ids(siemplify, ids_file_name='ids.json', max_hours_backwards=24):
    """
    Read existing (already seen) alert ids from the ids.json file
    :param siemplify: {Siemplify} Siemplify object.
    :param max_hours_backwards: {int} Max amount of hours to keep ids in the file (to prevent it from getting too big)
    :param ids_file_name: {str} The name of the ids file
    :return:{dict} A dict describing the already seen ids {id: the unixtime when it was first seen}
    """
    ids_file_path = os.path.join(siemplify.run_folder, ids_file_name)
    siemplify.LOGGER.info("Fetching existing IDs from: {0}".format(ids_file_path))

    try:
        if not os.path.exists(ids_file_path):
            siemplify.LOGGER.info("Ids file doesn't exist at path {}".format(ids_file_path))
            return {}

        with open(ids_file_path, 'r') as f:
            siemplify.LOGGER.info("Reading existing ids from ids file")
            existing_ids = json.loads(f.read())

            filtered_ids = {}
            # Insert IDs that did not passed time retention time limit.
            for alert_id, timestamp in existing_ids.items():
                if timestamp > arrow.utcnow().shift(hours=-max_hours_backwards).timestamp * 1000:
                    filtered_ids[alert_id] = timestamp

            return filtered_ids

    except Exception as e:
        siemplify.LOGGER.error("Unable to read ids file: {}".format(e))
        siemplify.LOGGER.exception(e)
        return {}


# Move to TIPCommon
def write_ids(siemplify, ids, ids_file_name='ids.json'):
    """
    Write ids to the ids file
    :param siemplify: {Siemplify} Siemplify object.
    :param ids_file_name: {str} The name of the ids file
    :param ids: {dict} The ids to write to the file
    """
    try:
        ids_file_path = os.path.join(siemplify.run_folder, ids_file_name)
        siemplify.LOGGER.info("Writing ids to file: {}".format(ids_file_path))

        if not os.path.exists(os.path.dirname(ids_file_path)):
            siemplify.LOGGER.info("Ids file doesn't exist at {}. Creating new file.".format(ids_file_path))
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
        siemplify.LOGGER.error("Failed writing IDs to IDs file, ERROR: {0}".format(e))
        siemplify.LOGGER.exception(e)


# Move to TIPCommon
def is_overflowed(siemplify, alert_info, is_test_run):
    """
    Check if overflowed
    :param siemplify: {Siemplify} Siemplify object.
    :param alert_info: {AlertInfo}
    :param is_test_run: {bool} Whether test run or not.
    :return: {bool}
    """
    try:
        return siemplify.is_overflowed_alert(
            environment=alert_info.environment,
            alert_identifier=alert_info.ticket_id,
            alert_name=alert_info.rule_generator,
            product=alert_info.device_product)

    except Exception as err:
        siemplify.LOGGER.error(
            'Error validation connector overflow, ERROR: {}'.format(err))
        siemplify.LOGGER.exception(err)
        if is_test_run:
            raise

    return False


# Move to TIPCommon
def save_timestamp(siemplify, alerts, timestamp_key='timestamp', incrementation_value=0, log_timestamp=True):
    """
        Save last timestamp for given alerts
        :param siemplify: {Siemplify} Siemplify object
        :param alerts: {list} The list of alerts to find the last timestamp
        :param timestamp_key: {str} key for getting timestamp from alert
        :param incrementation_value: {int} The value to increment last timestamp by milliseconds
        :param log_timestamp: {bool} Whether log timestamp or not
        :return: {bool} Is timestamp updated
        """
    if not alerts:
        siemplify.LOGGER.info('Timestamp is not updated since no alerts fetched')
        return False
    alerts = sorted(alerts, key=lambda alert: int(getattr(alert, timestamp_key)))
    last_timestamp = int(getattr(alerts[-1], timestamp_key)) + incrementation_value

    if log_timestamp:
        siemplify.LOGGER.info('Saving timestamp:{}'.format(last_timestamp))

    siemplify.save_timestamp(new_timestamp=last_timestamp)
    return True


def save_fail(path, name, content, overwrite):
    """
    Save file to local path
    :param path: {str} Path of the folder, where files should be saved
    :param name: {str} File name to be saved
    :param content: {str} File content
    :param overwrite: {bool} Specifies if overwrite the existing file or no
    :return: {str} Path to the downloaded file
    """
    # Raise an error if path does not exist
    if not os.path.exists(path):
        raise Exception("Specified path doesn't exist.")

    # File local path
    local_path = os.path.join(path, name)
    local_path ="{}{}".format(local_path,".zip")

    if not overwrite and os.path.exists(local_path):
        raise SentinelOneV2AlreadyExistsError(local_path)

    with open(local_path, 'wb') as file:
        file.write(content)
        file.close()

    return local_path


def filter_items(items, filter_key=None, filter_logic=None, filter_value=None, limit=None):
    """
    Filter list of items
    :param items: {list} list of items to filter
    :param filter_key: {str} filter key that should be used for filtering
    :param filter_logic: {str} filter logic that should be applied
    :param filter_value: {str} filter value that should be used for filtering
    :param limit: {int} limit for items
    """
    if FILTER_KEY_MAPPING.get(filter_key) and FILTER_STRATEGY_MAPPING.get(filter_logic) and filter_value:
        items = [item for item in items
                 if FILTER_STRATEGY_MAPPING[filter_logic](getattr(item, FILTER_KEY_MAPPING.get(filter_key)), filter_value)]

    return items[:limit] if limit else items
