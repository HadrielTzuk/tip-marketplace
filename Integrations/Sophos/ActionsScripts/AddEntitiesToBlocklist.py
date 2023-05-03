from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from SophosManager import SophosManager
from constants import SHA256_LENGTH, INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, ADD_ENTITIES_TO_BLOCKLIST_ACTIONS_SCRIPT_NAME
from SiemplifyDataModel import EntityTypes
from SophosExceptions import HashAlreadyOnBlocklist

SUPPORTED_ENTITY_TYPES = [EntityTypes.FILEHASH]

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_ENTITIES_TO_BLOCKLIST_ACTIONS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True, input_type=unicode)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Client ID",
                                            is_mandatory=True, input_type=unicode)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Client Secret",
                                                is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    # Action parameters
    comment = extract_action_param(siemplify, param_name="Comment", print_value=True, is_mandatory=True, input_type=unicode)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    failed_entities = []
    already_added_hash = []
    
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]
    
    try:  
        manager = SophosManager(api_root=api_root, client_id=client_id, client_secret=client_secret,
                                verify_ssl=verify_ssl, test_connectivity=True)

        for entity in suitable_entities:
            siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))

            if len(entity.identifier) != SHA256_LENGTH:
                siemplify.LOGGER.error(u"Hash type of hash: {} is not supported. Provide SHA-256 Hash.".format(entity.identifier))
                continue
            try:
                manager.add_hash_to_blocklist(hash_entity=entity.identifier, comment=comment)
                successful_entities.append(entity)
                
            except HashAlreadyOnBlocklist as e:
                siemplify.LOGGER.info(u"Entity {} was already on the blocklist in {}.".format(entity.identifier,INTEGRATION_NAME))
                already_added_hash.append(entity)
                
            except Exception as e:
                siemplify.LOGGER.error(e)
                failed_entities.append(entity)
            
            siemplify.LOGGER.info(u"Finished processing entity {}".format(entity.identifier))

                
        if successful_entities:
            output_message = u"Successfully added the following entities to blocklist in {}: \n{}".format(INTEGRATION_NAME,
                        "\n".join([entity.identifier for entity in successful_entities]))         

            if failed_entities:
                output_message += u"\nAction wasn't able to add the following entities to blocklist in {}: \n{}".format(INTEGRATION_NAME,
                        "\n".join([entity.identifier for entity in failed_entities]))

            if already_added_hash:
                output_message += u"\nThe following entities are already a part of the blocklist in {}: \n{}".format(INTEGRATION_NAME,
                        "\n".join([entity.identifier for entity in already_added_hash]))      
            
        else:
            result = False
            output_message = u"None of the provided entities were added to the blocklist in {}.".format(INTEGRATION_NAME)  
            
    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(ADD_ENTITIES_TO_BLOCKLIST_ACTIONS_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = u"Error executing action {}. Reason: {}".format(ADD_ENTITIES_TO_BLOCKLIST_ACTIONS_SCRIPT_NAME, e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}".format(status))
    siemplify.LOGGER.info(u"Result: {}".format(result))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
