import copy
import os
import re
import uuid

from TIPCommon import extract_action_param
from ioc_writer import ioc_api

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtilitiesManager import SiemplifyUtilitiesManager
from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime
from constants import (
    PROVIDER_NAME,
    EXPORT_ENTITIES_AS_OPENIOC_FILE_SCRIPT_NAME,
    IOC_MAPPINGS,
    IOC_FILE_AUTHOR,
    IOC_FILE_DESCRIPTION,
    NEGATABLE_IOCS,
    MD5_HASH_LENGTH,
    SHA1_HASH_LENGTH,
    SHA256_HASH_LENGTH,
    IOC_EXTENSION,
    MD5_HASH,
    SHA1_HASH,
    SHA256_HASH,
    IP_ADDRESS,
    IS_USER_ENABLED,
    DOMAIN,
    HOSTNAME,
    MAC_ADDRESS,
    OS,
    ASSET_TYPE,
    PROCESSOR,
    USERNAME,
    USER_GROUPS,
    NUMERIC_REGEX,
    UNDERSCORE,
    USER_DISPLAY_NAME,
    HOST_MEMORY,
    HOST_OS_VERSION,
    USER_EMAIL,
    URL
)

SUPPORTED_IOC_ENTITY_DETAILS = {  # map entity to its supported mappable ioc entity details properties
    EntityTypes.FILEHASH: [MD5_HASH, SHA1_HASH, SHA256_HASH],
    EntityTypes.ADDRESS: [HOSTNAME],
    EntityTypes.HOSTNAME: [IP_ADDRESS, DOMAIN, MAC_ADDRESS, OS, HOST_OS_VERSION, HOST_MEMORY, PROCESSOR, ASSET_TYPE],
    EntityTypes.USER: [USERNAME, USER_DISPLAY_NAME, USER_GROUPS, DOMAIN, USER_EMAIL, IS_USER_ENABLED],
    EntityTypes.URL: [IP_ADDRESS]
}


def match_entity_properties(entity, attributes):
    """
    Match entity's additional properties with specific attributes
    :param entity: {DomainEntityInfo} Siemplify entity to match attributes in
    :param attributes: {[str]} List of attributes to match in the entity's additional properties
    :return: {[(str, str, str, str, bool)]} List of tuples representing matched entity properties.
    First value is property name, second value is the property value, third value is the correlated ioc search field type, fourth value is the ioc
    search field content and fifth value is whether the property should be negated or not.
    """
    entity_properties = copy.deepcopy(entity.additional_properties)
    matched_properties = []
    for prop, prop_value in entity_properties.items():
        splitted_entity_property = prop.split(UNDERSCORE)
        if re.search(NUMERIC_REGEX, splitted_entity_property[-1]):  # exclude property's numeric suffix of flatted list
            splitted_entity_property = splitted_entity_property[:-1]
        entity_property = splitted_entity_property[-1].lower()
        if entity_property:
            for attribute in attributes:
                negate = False
                # In case of ipAddress or ip_address for example we will try to match both
                if attribute.replace(UNDERSCORE, u"").lower() == entity_property or \
                        (UNDERSCORE in attribute and attribute.lower() == UNDERSCORE.join(splitted_entity_property[-2:]).lower()):
                    if attribute in NEGATABLE_IOCS:
                        negate = True
                    if isinstance(IOC_MAPPINGS[attribute], list):
                        for ioc_content_type, ioc_attr in IOC_MAPPINGS[attribute]:
                            matched_properties.append((prop, prop_value, ioc_content_type, ioc_attr, negate))
                    else:
                        matched_properties.append((prop, prop_value, IOC_MAPPINGS[attribute][0], IOC_MAPPINGS[attribute][1], negate))
    return matched_properties


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(PROVIDER_NAME, EXPORT_ENTITIES_AS_OPENIOC_FILE_SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # Action configuration
    ioc_name = extract_action_param(siemplify, param_name=u"IOC Name", is_mandatory=False, print_value=True)
    export_folder_path = extract_action_param(siemplify, param_name=u"Export Folder Path", is_mandatory=True, print_value=True)
    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    # Action results
    result_value = False
    status = EXECUTION_STATE_COMPLETED
    output_message = u""

    # Processing
    successful_entities = []
    failed_entities = []

    try:
        iocid = u"OpenIOC_{}".format(str(uuid.uuid4()))
        ioc = ioc_api.IOC(name=ioc_name, description=IOC_FILE_DESCRIPTION, author=IOC_FILE_AUTHOR, iocid=iocid)
        extract_ioc_document_from_search_term = SiemplifyUtilitiesManager.extract_ioc_document_from_search_term
        supported_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_IOC_ENTITY_DETAILS.keys()]

        if supported_entities:
            for entity in supported_entities:
                if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                    siemplify.LOGGER.error(u"Timed out. execution deadline ({}) has passed".format(
                        convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                    status = EXECUTION_STATE_TIMEDOUT
                    break
                try:
                    siemplify.LOGGER.info(u"Started processing entity {}".format(entity.identifier))
                    indicator_item_nodes = []

                    if entity.entity_type == EntityTypes.HOSTNAME:
                        ioc_term_type, ioc_search = IOC_MAPPINGS[HOSTNAME]
                    elif entity.entity_type == EntityTypes.ADDRESS:
                        ioc_term_type, ioc_search = IOC_MAPPINGS[IP_ADDRESS]
                    elif entity.entity_type == EntityTypes.FILEHASH:
                        if len(entity.identifier) == MD5_HASH_LENGTH:
                            ioc_term_type, ioc_search = IOC_MAPPINGS[MD5_HASH]
                        elif len(entity.identifier) == SHA1_HASH_LENGTH:
                            ioc_term_type, ioc_search = IOC_MAPPINGS[SHA1_HASH]
                        elif len(entity.identifier) == SHA256_HASH_LENGTH:
                            ioc_term_type, ioc_search = IOC_MAPPINGS[SHA256_HASH]
                        else:
                            siemplify.LOGGER.info(u"Hash \"{}\" is of unsupported type. Skipping...".format(entity.identifier))
                            failed_entities.append(entity)
                            continue
                    elif entity.entity_type == EntityTypes.USER:
                        ioc_term_type, ioc_search = IOC_MAPPINGS[USERNAME]
                    elif entity.entity_type == EntityTypes.URL:
                        ioc_term_type, ioc_search = IOC_MAPPINGS[URL]
                    else:
                        siemplify.LOGGER.info(
                            u"Unsupported entity {} of type {} was found. Skipping...".format(entity.identifier, entity.entity_type))
                        continue

                    # export entity identifier
                    indicator_item_nodes.append(
                        ioc_api.make_indicatoritem_node(condition=ioc_api.IS,
                                                        document=extract_ioc_document_from_search_term(ioc_search),
                                                        search=ioc_search, content_type=ioc_term_type, content=entity.identifier))

                    # export entity details
                    for property, property_value, ioc_content_type, ioc_search, negate in \
                            match_entity_properties(entity, SUPPORTED_IOC_ENTITY_DETAILS[entity.entity_type]):
                        if property_value.lower() in [u"true", u"false"]:
                            property_value = property_value.lower()
                        if property_value in [item_node[1].text for item_node in indicator_item_nodes]:
                            continue
                        indicator_item_nodes.append(
                            ioc_api.make_indicatoritem_node(condition=ioc_api.IS,
                                                            document=extract_ioc_document_from_search_term(ioc_search),
                                                            search=ioc_search, content_type=ioc_content_type, content=property_value,
                                                            negate=negate))

                    if len(indicator_item_nodes) > 1:
                        second_level_and_node = ioc_api.make_indicator_node(ioc_api.OR)
                        for indicator_item in indicator_item_nodes:
                            second_level_and_node.append(indicator_item)
                        ioc.top_level_indicator.append(second_level_and_node)
                        successful_entities.append(entity)
                    else:
                        if indicator_item_nodes:
                            ioc.top_level_indicator.append(indicator_item_nodes[0])
                            successful_entities.append(entity)
                        else:
                            siemplify.LOGGER.info(u"No indicator items were created for entity {}".format(entity.identifier))
                            failed_entities.append(entity)
                    siemplify.LOGGER.info(u"Finished processing entity")
                except Exception as error:
                    failed_entities.append(entity)
                    siemplify.LOGGER.error(u"An error occurred on entity {}".format(entity.identifier))
                    siemplify.LOGGER.exception(error)

            if successful_entities:
                if not ioc.write_ioc_to_file(export_folder_path):
                    raise Exception(
                        u"Failed to write out entities to IOC file. Please check that provided \"Export Folder Path\" parameter is valid.")
                output_message += u"Successfully created an OpenIOC file based on the provided entities:\n   {}".format(
                    u"\n   ".join([entity.identifier for entity in successful_entities])
                )
                result_value = True
                exported_ioc_report_path = os.path.join(export_folder_path, u"{}.{}".format(iocid, IOC_EXTENSION))
                if failed_entities:
                    output_message += u"\n\nAction was not able to export the following entities to an OpenIOC file:\n   {}".format(
                        u"\n   ".join([entity.identifier for entity in failed_entities])
                    )
                try:
                    siemplify.add_attachment(exported_ioc_report_path)
                except Exception as error:
                    siemplify.LOGGER.error(u"Failed to attach attachment {} to the case wall. Error: {}".format(exported_ioc_report_path, str(error)))
                    siemplify.LOGGER.exception(error)
                siemplify.result.add_result_json({u"absolute_file_path": exported_ioc_report_path})
            else:
                output_message += u"No entities were successful exported as OpenIOC file."
        else:
            output_message = u"Action wasn't able to create an OpenIOC file, because there are no supported entities in the action execution scope."

    except Exception as error:
        output_message = u"Error executing action \"{}\". Reason: {}".format(EXPORT_ENTITIES_AS_OPENIOC_FILE_SCRIPT_NAME, str(error))
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == u'__main__':
    main()
