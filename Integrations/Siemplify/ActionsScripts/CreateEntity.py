from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import MAX_DELIMITER_SIZE


def check_if_entity_exists(siemplify, target_entities, entity_identifier, entity_type):
    """
    Verify if entity with such identifier and type already exists within the case.
    :param siemplify: {SiemplifyAction} siemplify action object
    :param target_entities: enumeration of case entities (e.g. siemplify.target_entities)
    :param entity_identifier: identifier of entity, which we're checking
    :param entity_type: the type of the entity, which we are checking
    :return: True if entity with such identifier and type exists already within case; False - otherwise
    """
    siemplify.LOGGER.info(
        "Checking if User entity {0} of type {1} exists in target entities.".format(entity_identifier, entity_type.strip().encode('utf-8')))
    for entity in target_entities:
        siemplify.LOGGER.info("Target Entity {0} {1}".format(entity.identifier.strip().encode('utf-8'), entity.entity_type.encode('utf-8')))
        if entity.identifier.strip().encode('utf-8') == entity_identifier and entity.entity_type.encode('utf-8') == \
                entity_type.strip().encode('utf-8'):
            siemplify.LOGGER.info("Found existing matching entity by type and identifier")
            return True
    return False


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "Create Entity"
    siemplify.LOGGER.info("-----------Action started--------------")

    entities_identifies = siemplify.parameters["Entities Identifies"]
    entity_type = siemplify.parameters["Entity Type"]
    is_internal = siemplify.parameters.get("Is Internal", 'false').lower() == 'true'
    is_suspicious = siemplify.parameters.get("Is Suspicious", 'false').lower() == 'true'
    delimiter = siemplify.parameters.get("Delimiter", '')

    is_enriched = False
    is_vulnerable = False
    result_value = 'true'
    status = EXECUTION_STATE_COMPLETED
    properties = {'is_new_entity': True}

    if len(delimiter) > 0:
        entities_identifies_list = entities_identifies.split(delimiter)
        if len(delimiter) > MAX_DELIMITER_SIZE:
            siemplify.LOGGER.info(
                "Warning: Delimiter is longer than {0} characters, it is working properly in the \"Create Entity\" action, but please note this is not supported in the mapping configuration".format(
                    MAX_DELIMITER_SIZE))
    else:
        entities_identifies_list = [entities_identifies]

    error_messages = []
    warning_messages = []
    success_entities = []
    for entity_identifier in entities_identifies_list:
        entity_identifier = entity_identifier.strip().encode('utf-8')
        if entity_identifier:
            try:
                if check_if_entity_exists(siemplify, siemplify.target_entities, entity_identifier, entity_type):
                    message = "Entity with identifier {0} hasn't been added to the case, as it already exists.".format(entity_identifier)
                    siemplify.LOGGER.info(message)
                    warning_messages.append(message)
                else:
                    siemplify.add_entity_to_case(entity_identifier, entity_type, is_internal, is_suspicious,
                                                 is_enriched, is_vulnerable, properties)
                    siemplify.LOGGER.info(
                        "Entity with identifier {0} {1} has been added to the case.".format(entity_identifier, entity_type))
                    success_entities.append(entity_identifier)
            except Exception as e:
                error_message = "Entity {0} Creation failed.".format(entity_identifier)
                siemplify.LOGGER.error(error_message)
                siemplify.LOGGER.exception(e)
                error_messages.append(error_message)

    if success_entities:
        output_message = '{0} created successfully.'.format(",".join(success_entities))
    else:
        output_message = 'No entities were created.'

    if warning_messages:
        output_message = "{0} \n WARNINGS: \n {1}".format(output_message, "\n".join(warning_messages))

    if error_messages:
        output_message = "{0} \n ERRORS: \n {1}".format(output_message, "\n".join(error_messages))
        status = EXECUTION_STATE_FAILED
        result_value = 'false'

    siemplify.LOGGER.info("-----------Action done--------------")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
