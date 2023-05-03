from MISPManager import MISPManager, URL, HOSTNAME, DOMAIN, USER, EMAIL_SUBJECT, THREAT_ACTOR, PHONE_NUMBER, FILENAME
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED, EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime, convert_dict_to_json_result_dict
from TIPCommon import extract_action_param, extract_configuration_param
from constants import ADD_ATTRIBUTE_SCRIPT_NAME, INTEGRATION_NAME, ATTRIBUTES_EXISTING_CATEGORY_TYPES, \
    FALLBACK_IP_TYPES_MAPPER, FALLBACK_EMAIL_TYPES_MAPPER, COMMUNITY, ATTRIBUTE_DISTRIBUTION, IP_TYPES, EMAIL_TYPES, \
    EMAIL_TYPE, DOMAIN_TYPE
from exceptions import MISPManagerInvalidCategoryError, MISPManagerEventIdNotFoundError, \
    MISPNotAcceptableNumberOrStringError
from utils import get_hash_type, get_domain_from_entity, get_entity_original_identifier, get_entity_type
from utils import adjust_categories
import re

SUITABLE_ENTITY_TYPES = [EntityTypes.HOSTNAME, EntityTypes.URL, EntityTypes.FILEHASH, EntityTypes.ADDRESS,
                         EntityTypes.USER, EntityTypes.FILENAME, EntityTypes.EMAILMESSAGE, EntityTypes.THREATCAMPAIGN,
                         EntityTypes.THREATACTOR, EntityTypes.PHONENUMBER]


def is_src(alert, identifier):
    for relation in alert.relations:
        if relation.from_identifier == identifier:
            return True


def is_dst(alert, identifier):
    for relation in alert.relations:
        if relation.to_identifier == identifier:
            return True


def is_valid_domain(domain_name):
    regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
    p = re.compile(regex)

    if domain_name is None:
        return False

    if re.search(p, domain_name):
        return True
    else:
        return False


def get_entity_type_for_request(siemplify, entity, identifier, extract_domain, entity_type_mapper):
    entity_type = entity_type_mapper[get_entity_type(entity, extract_domain)]

    if entity.entity_type == EntityTypes.HOSTNAME or entity.entity_type == DOMAIN_TYPE:
        # So, first action should try to add the domain type. If it fails for “domain“ attribute type,
        # it should do it for target-user.
        entity_type = entity_type if is_valid_domain(identifier) else entity_type_mapper[EntityTypes.USER]
    # If Siemplify current alert has relations use entity type by checking from siemplify's alert and set the type
    # otherwise let as is
    if entity.entity_type == EntityTypes.ADDRESS:
        if siemplify.current_alert.relations:
            if is_src(siemplify.current_alert, identifier):
                entity_type = IP_TYPES[FALLBACK_IP_TYPES_MAPPER['ip-src']]
            if is_dst(siemplify.current_alert, identifier):
                entity_type = IP_TYPES[FALLBACK_IP_TYPES_MAPPER['ip-dst']]

    if entity.entity_type == EMAIL_TYPE:
        if siemplify.current_alert.relations:
            if is_src(siemplify.current_alert, identifier):
                entity_type = FALLBACK_EMAIL_TYPES_MAPPER['email-src']
            if is_dst(siemplify.current_alert, identifier):
                entity_type = FALLBACK_IP_TYPES_MAPPER['email-dst']

    if not entity_type and entity.entity_type == EntityTypes.FILEHASH:
        # In case of filehash we should get entity_type by filehash length or in case of ssdeep hash with regexp
        entity_type = get_hash_type(identifier)

    return entity_type


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_ATTRIBUTE_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root")
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key")
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Use SSL",
                                          default_value=False, input_type=bool)
    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="CA Certificate File - parsed into Base64 String")

    event_id = extract_action_param(siemplify, param_name="Event ID", is_mandatory=True, print_value=True)
    category = adjust_categories(extract_action_param(siemplify, param_name="Category", print_value=True))
    distribution = extract_action_param(siemplify, param_name="Distribution", print_value=True, default_value=COMMUNITY)
    to_ids = extract_action_param(siemplify, param_name="For Intrusion Detection System", print_value=True,
                                  input_type=bool, default_value=False)
    comment = extract_action_param(siemplify, param_name="Comment", print_value=True)
    fallback_ip_type = extract_action_param(siemplify, param_name="Fallback IP Type", print_value=True,
                                            default_value=FALLBACK_IP_TYPES_MAPPER['ip-src'])
    fallback_email_type = extract_action_param(siemplify, param_name="Fallback Email Type", print_value=True,
                                               default_value=FALLBACK_EMAIL_TYPES_MAPPER['email-src'])
    extract_domain = extract_action_param(siemplify, param_name="Extract Domain", print_value=True,
                                          input_type=bool, default_value=True)
    id_type = "ID" if event_id.isdigit() else "UUID"

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    successful_entities, failed_entities, json_results = [], [], []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUITABLE_ENTITY_TYPES]

    entity_type_mapper = {
        EntityTypes.HOSTNAME: HOSTNAME,
        EntityTypes.URL: URL,
        EntityTypes.FILEHASH: '',
        EntityTypes.ADDRESS: IP_TYPES[fallback_ip_type],
        EntityTypes.USER: USER,
        EntityTypes.FILENAME: FILENAME,
        EntityTypes.EMAILMESSAGE: EMAIL_SUBJECT,
        EntityTypes.THREATCAMPAIGN: THREAT_ACTOR,
        EntityTypes.THREATACTOR: THREAT_ACTOR,
        EntityTypes.PHONENUMBER: PHONE_NUMBER,
        EMAIL_TYPE: EMAIL_TYPES[fallback_email_type],
        DOMAIN_TYPE: DOMAIN
    }

    try:
        if distribution.lower() not in map(str, tuple(ATTRIBUTE_DISTRIBUTION.keys()) + tuple(ATTRIBUTE_DISTRIBUTION.values())):
            raise MISPNotAcceptableNumberOrStringError('Distribution',
                                                       acceptable_strings=ATTRIBUTE_DISTRIBUTION.keys(),
                                                       acceptable_numbers=ATTRIBUTE_DISTRIBUTION.values())
        distribution = int(ATTRIBUTE_DISTRIBUTION[distribution.lower()] if not distribution.isdigit() else distribution)

        if category and category.lower() not in ATTRIBUTES_EXISTING_CATEGORY_TYPES:
            raise MISPManagerInvalidCategoryError("Invalid value was provided for the parameter \"Category\"."
                                                  "Acceptable values: {}."
                                                  .format(', '.join([category.capitalize()
                                                                     for category in ATTRIBUTES_EXISTING_CATEGORY_TYPES])))

        manager = MISPManager(api_root, api_token, use_ssl, ca_certificate)
        event_id = manager.get_event_by_id_or_raise(event_id).id

        for entity in suitable_entities:
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error("Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break

            # Get original identifier from entity
            identifier = get_entity_original_identifier(entity) \
                if not (extract_domain and entity.entity_type == EntityTypes.URL) \
                else get_domain_from_entity(get_entity_original_identifier(entity))

            # Get entity type
            entity_type = get_entity_type_for_request(siemplify, entity, identifier, extract_domain, entity_type_mapper)
            try:
                siemplify.LOGGER.info("Started processing entity: {}".format(identifier))

                siemplify.LOGGER.info("Adding {} attribute for event {}".format(identifier, event_id))
                if entity_type:
                    attribute = manager.add_attribute(event_id=event_id, value=identifier, type=entity_type,
                                                      category=category, to_ids=to_ids, distribution=distribution,
                                                      comment=comment)
                    json_results.append(attribute)
                    successful_entities.append(identifier)
                else:
                    failed_entities.append(identifier)
                siemplify.LOGGER.info("Finished processing entity {0}".format(identifier))

            except Exception as e:
                failed_entities.append(identifier)
                siemplify.LOGGER.error("An error occurred on entity: {}.\n{}.".format(identifier, e))
                siemplify.LOGGER.exception(e)

        if json_results:
            siemplify.result.add_result_json([{'Attribute': result.as_json()} for result in json_results])

        if successful_entities:
            output_message += "Successfully added the following attributes based on entities to the event with " \
                              "{} {} in {}: \n {} \n"\
                .format(id_type, event_id, INTEGRATION_NAME, ', '.join(successful_entities))

        if failed_entities:
            output_message += "Action wasn’t able to add the following attributes based on entities to the event " \
                              "with {} {} in {}: \n {} \n"\
                .format(id_type, event_id, INTEGRATION_NAME, ', '.join(failed_entities))

        if not successful_entities:
            output_message = "No attributes based on entities were added to the event with {} {} in {}"\
                .format(id_type, event_id, INTEGRATION_NAME)
            result_value = False

    except Exception as e:
        output_message = "Error executing action {}. Reason: ".format(ADD_ATTRIBUTE_SCRIPT_NAME)
        output_message += 'Event with {} {} was not found in {}'.format(id_type, event_id, INTEGRATION_NAME) \
            if isinstance(e, MISPManagerEventIdNotFoundError) else str(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        "\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
