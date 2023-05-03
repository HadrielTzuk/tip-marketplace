import os
import json
import math
from TIPCommon import platform_supports_db, write_content, read_content

CUSTOM_CONFIGURATION_FILE_NAME = "severity_map_config.json"
SEVERITY_CUSTOM_KEY_NAME = 'severity'
DEFAULT_SEVERITY_VALUE = 50
CUSTOM_MAPPING_CONFIGURATION = {}
CONFIGURATION_DATA = {}


def load_custom_severity_configuration(siemplify, severity_field_name, file_path=CUSTOM_CONFIGURATION_FILE_NAME):
    global DEFAULT_SEVERITY_VALUE
    global CUSTOM_MAPPING_CONFIGURATION
    global CONFIGURATION_DATA

    conf_data = read_content(siemplify, file_name=file_path, db_key=SEVERITY_CUSTOM_KEY_NAME)
    DEFAULT_SEVERITY_VALUE = conf_data.get("Default", DEFAULT_SEVERITY_VALUE)
    CUSTOM_MAPPING_CONFIGURATION = conf_data.get(severity_field_name, CUSTOM_MAPPING_CONFIGURATION)
    conf_data = {
        "Default": DEFAULT_SEVERITY_VALUE
    }
    if severity_field_name:
        conf_data[severity_field_name] = CUSTOM_MAPPING_CONFIGURATION
    CONFIGURATION_DATA = conf_data
    write_content(siemplify, conf_data, file_name=file_path, db_key=SEVERITY_CUSTOM_KEY_NAME)


def map_severity_value(severity_field_name, severity_value):
    if severity_field_name:
        severity_score = DEFAULT_SEVERITY_VALUE
        try:
            severity_value = float(severity_value)
        except:
            pass
        if isinstance(severity_value, float):
            severity_score = math.ceil(severity_value)
        elif isinstance(severity_value, str):
            severity_dict = CONFIGURATION_DATA.get(severity_field_name)
            if severity_dict:
                severity_score = severity_dict.get(severity_value, DEFAULT_SEVERITY_VALUE)

        if severity_score > 100:
            return 100
        elif severity_score < 0:
            return -1
        else:
            return int(severity_score)
    return DEFAULT_SEVERITY_VALUE


def get_field_value(flat_alert, field_name, default_value=None):
    """
    Get the value from flattened alert by field name different notations
    Possible notations: host.name, _source_host_name, host_name
    :param flat_alert: An ES flattened alert
    :param field_name: The field name
    :param default_value: The default value
    :return: The field value
    """
    try:
        # Try with exact match
        return flat_alert[field_name]
    except:
        try:
            # Try with _source_ prefix
            return flat_alert["_source_{}".format(field_name)]
        except:
            try:
                # Try with _source_ prefix, and _ instead of .
                return flat_alert["_source_{}".format(field_name.replace(".", "_"))]
            except:
                # If nothing match return the default value if provided, raise otherwise
                if default_value is not None:
                    return default_value
                else:
                    raise
