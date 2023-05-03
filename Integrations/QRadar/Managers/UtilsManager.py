import os
import json
from constants import (
    OFFENSE_EVENTS_DB_KEY,
    RULE_ID_NAME_MAPPING_FILE,
    OFFENSE_EVENTS_FILE,
    RULE_ID_NAME_MAPPING_DB_KEY,
    OFFENSE_EVENTS_DATA_FILE,
    OFFENSE_EVENTS_DATA_DB_KEY,
    MAP_FILE,
    MAP_OBJECT_FIELDS
)
from exceptions import QRadarInvalidRuleException
from SiemplifyUtils import unix_now
from TIPCommon import platform_supports_db, read_content, write_content
from constants import OFFENSES_CONNECTOR_NAME


def get_environment_for_correlations_connector(siemplify, original_env):
    """
       Get mapped environment alias from mapping file
       :param original_env: {str} The environment to try to resolve\
       :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class.
       :return: {str} The resolved alias (if no alias - returns the original env)
    """
    if platform_supports_db(siemplify):
        return original_env

    else:
        # Validating map.json
        map_file_path = os.path.join(siemplify.run_folder, MAP_FILE)
        try:
            if not os.path.exists(map_file_path):
                with open(map_file_path, 'w+') as map_file:
                    map_file.write(json.dumps(
                        {"Original environment name": "Desired environment name",
                         "Env1": "MyEnv1"}))
                    siemplify.LOGGER.info(f"Mapping file was created at {map_file}")
        except Exception as e:
            siemplify.LOGGER.error(f"Unable to create mapping file: {e}")
            siemplify.LOGGER.exception(e)
        # Using the map.json
        try:
            with open(map_file_path, 'r+') as map_file:
                mappings = json.loads(map_file.read())
        except Exception as e:
            siemplify.LOGGER.error(f"Unable to read environment mappings: {e}")
            mappings = {}

        if not isinstance(mappings, dict):
            siemplify.LOGGER.LOGGER.error("Mappings are not in valid format. Environment will not be mapped.")
            return original_env

        return mappings.get(original_env, original_env)


def load_offense_events(siemplify, offenses_padding_period):
    """
       Load already seen events of rules and offenses.
       Can load from file or db - depending on platform version
       :param offenses_padding_period: the self.param.offenses_padding_period
        attribute of the BaseConnector object in the connector script
       :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class.
       :return: {dict} The offense events, in the following format -

        For the offenses connector:

           {
                "last_offense_padding_period": int,
                "offenses": {

                     "{offense ID}": {

                          "last_update_time": "unix time",
                          "no_new_events_timer_start_time": "unix time",
                          "events": {

                               "0A65C62595A803AF": {
                                    "timestamp": unixtime
                               },

                               "51528BECB2B87D25": {
                                    "timestamp": unixtime
                               },

                               "BCF57E7FCBE55F82": {
                                   "timestamp": unixtime
                               }
                          }
                     },
                     "{Offense ID}": {...}

                     "rules_events_counter": {
                            "None": 0
                     }
                }
           }


       For the Correlations Connector V2:

            {
                 "last_offense_padding_period": int,
                 "offenses": {

                      "{offense ID}": {

                           "last_update_time": "unix time",
                           "no_new_events_timer_start_time": "unix time",
                           "rules": {

                                "{Rule ID}": {

                                    "events": {
                                    "0A65C62595A803AF": unixtime,
                                    "51528BECB2B87D25": unixtime,
                                    "BCF57E7FCBE55F82": unixtime
                                    },

                                "{Rule ID}": {

                                    "events": {
                                        "51528BECB2B87D25": unixtime,
                                        "BCF57E7FCBE55F82": unixtime
                                    }
                                }
                           }
                      },
                      "{Offense ID}": {...}
                 }
            }
   """
    siemplify.LOGGER.info("Reading offense events")
    return read_content(
        siemplify=siemplify,
        file_name=OFFENSE_EVENTS_FILE,
        db_key=OFFENSE_EVENTS_DB_KEY,
        default_value_to_return={"last_offense_padding_period": offenses_padding_period, "offenses": {}}
    )


def save_offense_events(siemplify, offenses_padding_period, offense_events):
    """
    Save the offense events into a file/db (changes dynamically)
    :param offenses_padding_period: The self.param.offenses_padding_period
           attribute of the BaseConnector object in the connector script
    :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class
    :param offense_events: The (filtered) offense events json to write into, and then save it to
    file/db.
    """
    siemplify.LOGGER.info("Saving offense events")
    write_content(
        siemplify=siemplify,
        content_to_write=offense_events,
        file_name=OFFENSE_EVENTS_FILE,
        db_key=OFFENSE_EVENTS_DB_KEY,
        default_value_to_set={"last_offense_padding_period": offenses_padding_period, "offenses": {}}
    )


def create_rule_mapping(siemplify, logger, is_whitelist_as_blacklist, calculate_hash, rules, connector_name=''):
    """
           Create rule ID to rule name mapping based on the current whitelist and "Use whitelist as a blacklist" parameter.
           Fetch the list of all rules from QRadar, and save the ID and name of rules that are in the whitelist if "Use whitelist as a blacklist"
           parameter is False, otherwise save all rules that are not in the whitelist
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
             "rules_id_name_mapping": {
               {
                 "latest_whitelist_hashsum": "0A65C62595A803AF6A07AD9EC5D88D2921795387",
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
    rules_mapping = {}
    blacklist_rule_names = []
    invalid_rules = []

    rules_to_map = siemplify.whitelist
    if connector_name == OFFENSES_CONNECTOR_NAME and not siemplify.whitelist:
        rules_to_map = [rule.name for rule in rules]

    for whitelisted_rule_name in rules_to_map:
        matching_rule = list(filter(lambda rule: rule.name == whitelisted_rule_name.strip(), rules))

        if matching_rule:
            matching_rule = matching_rule[0]
            if is_whitelist_as_blacklist:
                blacklist_rule_names.append(matching_rule.name)
                continue
            rules_mapping[str(matching_rule.id)] = matching_rule.name
        else:
            invalid_rules.append(whitelisted_rule_name)
            logger.info("Rule \"{}\" doesn't exist in QRadar. Skipping rule.".format(whitelisted_rule_name))

    if rules_to_map and len(invalid_rules) == len(rules_to_map):
        raise QRadarInvalidRuleException("Connector failed to run because the  offense rule(s) provided in the"
                                         " whitelist section (dynamic list) is (are) not valid.")

    if is_whitelist_as_blacklist:
        logger.info("Creating rules mapping in blacklist mode".format(rules_to_map))
        for rule in rules:
            if rule.name not in blacklist_rule_names:
                rules_mapping[str(rule.id)] = rule.name

    logger.debug("RULES TO MAP: {}".format(', '.join(rules_mapping.values())))

    mapping = {
        "rules_id_name_mapping": {
            "latest_whitelist_hashsum": calculate_hash,
            "last_update_timestamp": unix_now(),
            "is_whitelist_as_blacklist": is_whitelist_as_blacklist,
            "mapping": rules_mapping if rules_mapping else {}
        }
    }
    logger.info("Saving rule mappings")
    write_content(siemplify, mapping, RULE_ID_NAME_MAPPING_FILE, RULE_ID_NAME_MAPPING_DB_KEY)
    return mapping


def load_events_data(siemplify):
    """
    Load events count from local json file
    :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class
    :return: {dict} ex.-{<offense_id>:{'count':<last_events_count>, 'last_event': <unixtime_timestamp>}
    """
    siemplify.LOGGER.info("Reading events' data")
    return read_content(siemplify, OFFENSE_EVENTS_DATA_FILE, OFFENSE_EVENTS_DATA_DB_KEY)


def write_events_data(siemplify, events_data_dict):
    """
    Save events count to local json file
    :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class
    :param events_data_dict: ex.-
    {
        <offense_id>:
            {
                'count':<last_events_count>,
                 'last_event': <unixtime_timestamp>
             }
    }
    :return:
    """
    siemplify.LOGGER.info("Saving events' data")
    write_content(siemplify, events_data_dict, OFFENSE_EVENTS_DATA_FILE, OFFENSE_EVENTS_DATA_DB_KEY)


def get_entity_original_identifier(entity):
    """
    Helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get('OriginalIdentifier', entity.identifier)


def convert_list_to_comma_string(values_list, delimiter=', '):
    """
    Convert list to comma-separated string
    :param values_list: String with comma-separated values
    :param delimiter: {str} Delimiter to join multi values to single value string.
    :return: List of values
    """
    return delimiter.join(values_list) if values_list and isinstance(values_list, list) else values_list


def get_case_priority_by_event_magnitude(max_magnitude):
    """
    Match magnitude to Siemplify value.
    :param max_magnitude {float}
    """
    if max_magnitude < 2:
        return -1
    elif max_magnitude < 4:
        return 40
    elif max_magnitude < 6:
        return 60
    elif max_magnitude < 8:
        return 80

    return 100


def search_for_key(lookup_key, lookup_data):
    all_matches = []

    for k, v in lookup_data.items():
        if type(v) is dict and k.lower() == lookup_key.lower():
            v["key"] = k
            all_matches.append(v)
        elif type(v) is list:
            for item in v:
                if type(item) is dict and k.lower() == lookup_key.lower():
                    item["key"] = k
                    all_matches.append(item)
    return all_matches


def search_for_value(lookup_value, lookup_data):
    all_matches = []
    for k, v in lookup_data.items():
        if type(v) is list:
            for item in v:
                if type(item) is dict and lookup_value.lower() == item.get("value", ""):
                    item["key"] = k
                    all_matches.append(item)
    return all_matches


def search_for_reference_table_value(lookup_value, lookup_data):
    all_matches = []
    outer_key = ""
    for k, v in get_all_dict_pairs(lookup_data):
        if type(v) is dict:
            if lookup_value in v.values():
                v["inner_key"] = k
                v["outer_key"] = outer_key
                all_matches.append(v)
            elif not is_map_object(v):
                outer_key = k
    return all_matches


def is_map_object(ref_object):
    if all(key in ref_object for key in MAP_OBJECT_FIELDS):
        return True


def get_all_dict_pairs(dict_data):
    for key, value in dict_data.items():
        yield key, value
        if type(value) is dict:
            yield from get_all_dict_pairs(value)
        elif type(value) is list:
            for item in value:
                yield from get_all_dict_pairs(item)


def convert_comma_separated_to_list(comma_separated):
    """
    Convert comma-separated string to list
    :param comma_separated: String with comma-separated values
    :return: List of values
    """
    return [item.strip() for item in comma_separated.split(',')] if comma_separated else []


def remove_none_params(**kwargs) -> dict:
    """
    Remove keys from dictionary that has the value None
    :param kwargs: key value arguments
    :return: {dict} dictionary without keys that have the value None
    """
    return {k: v for k, v in kwargs.items() if v is not None}

