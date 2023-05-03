from SiemplifyUtils import output_handler
import re
import validators
from SiemplifyAction import SiemplifyAction
from TrendMicroCloudAppSecurityManager import TrendMicroCloudAppSecurityManager
from TIPCommon import extract_configuration_param
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    ADD_ENTITIES_TO_BLOCKLIST_ACTION,
    SHA1_HASH_LENGTH,
    EMAIL_REGEX,
    DISPLAY_INTEGRATION_NAME
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_ENTITIES_TO_BLOCKLIST_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Root", is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Key", is_mandatory=True, print_value=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""

    failed_entities = []
    successful_entities = [] 
    entities_already_blocked = []
    found_target_entities = False

    try:
        trend_manager = TrendMicroCloudAppSecurityManager(api_root=api_root, api_key=api_key, verify_ssl=verify_ssl)
        already_blocked_entities = trend_manager.get_blocked_entities()
        
        for entity in siemplify.target_entities: 
            block_entity = False
            if entity.entity_type == EntityTypes.URL:
                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))  
                found_target_entities = True
                if validators.url(entity.identifier): #the endpoint only supports valid URLs
                    if entity.identifier.lower() not in map(str.lower, already_blocked_entities.urls):   
                        block_entity = True
                    else:
                        siemplify.LOGGER.info("Entity: {} is already in blocklist.".format(entity.identifier))
                        entities_already_blocked.append(entity)     
                else:
                    siemplify.LOGGER.info("Entity type URL: {} is in incorrect format.".format(entity.identifier))
                    
            if entity.entity_type == EntityTypes.USER:
                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))  
                found_target_entities = True
                if re.search(EMAIL_REGEX, entity.identifier.lower()):
                    if entity.identifier.lower() not in map(str.lower, already_blocked_entities.senders):
                        block_entity = True
                    else:
                        siemplify.LOGGER.info("Entity: {} is already in blocklist.".format(entity.identifier))
                        entities_already_blocked.append(entity)
                else:
                    siemplify.LOGGER.info("Entity type USER: {} is in incorrect format.".format(entity.identifier))

            if entity.entity_type == EntityTypes.FILEHASH and entity.entity_type:
                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))  
                found_target_entities = True
                if entity.identifier.lower() not in map(str.lower, already_blocked_entities.hashes):
                    if len(entity.identifier) == SHA1_HASH_LENGTH:
                        block_entity = True 
                else:
                    siemplify.LOGGER.info("Entity: {} is already in blocklist.".format(entity.identifier))
                    entities_already_blocked.append(entity)

            if block_entity:
                try:
                    trend_manager.add_entities_to_blocklist(entity_type=entity.entity_type, entity_to_remove=entity.identifier)
                    successful_entities.append(entity)
                    siemplify.LOGGER.info("Finished processing entity {0}".format(entity.identifier))
                except Exception as e:
                    failed_entities.append(entity)
                    siemplify.LOGGER.error("An error occurred on entity {0}".format(entity.identifier))
                    siemplify.LOGGER.exception(e)                    
                        
        if entities_already_blocked:
            output_message += "\nThe following entities are already a part of blocklist in {}: {}.".format(DISPLAY_INTEGRATION_NAME,
                    "\n".join([entity.identifier for entity in entities_already_blocked]))            
    
        if not successful_entities and not failed_entities and not found_target_entities:
            result_value = False
            output_message += "\nNo entities were added using information from {}.".format(DISPLAY_INTEGRATION_NAME)                 
        
        if successful_entities:
            output_message += "\nSuccessfully added the following entities to blocklist in {}: {}".format(DISPLAY_INTEGRATION_NAME,
                    "\n".join([entity.identifier for entity in successful_entities]))

            if failed_entities:
                output_message += "\nAction wasn't able to add the following entities to blocklist in {}: {}".format(DISPLAY_INTEGRATION_NAME,
                            "\n".join([entity.identifier for entity in failed_entities]))  
            
                
    except Exception as e:
        output_message += 'Error executing action {}. Reason: {}.'.format(ADD_ENTITIES_TO_BLOCKLIST_ACTION, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
