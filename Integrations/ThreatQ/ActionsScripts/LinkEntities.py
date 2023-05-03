from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyDataModel import EntityTypes
from ThreatQManager import ThreatQManager

from constants import (
    INTEGRATION_NAME,
    LINK_ENTITIES_SCRIPT,
    EMAIL_REGEX
)
from ThreatQUtils import *
import re
import itertools

ENTITY_INDICATORS = [EntityTypes.CVE, EntityTypes.ADDRESS, EntityTypes.URL,EntityTypes.FILEHASH,EntityTypes.USER]

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LINK_ENTITIES_SCRIPT
    result_value = True
    execution_status = EXECUTION_STATE_COMPLETED
    output_message = u""
    siemplify.LOGGER.info('=' * 10 + ' Main - Param Init ' + '=' * 10)

    server_address = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="ServerAddress"
    )

    client_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="ClientId"
    )

    username = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Username"
    )

    password = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Password"
    )
    
    siemplify.LOGGER.info('=' * 10 + ' Main - Started ' + '=' * 10)
    successful_entities = []
    failed_entities = []
    json_results = {}
    objects_to_link = {}

    try:
        threatq_manager = ThreatQManager(server_address, client_id, username, password)
        
        for entity in siemplify.target_entities:
            siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
            
            if entity.entity_type in ENTITY_INDICATORS or re.search(EMAIL_REGEX, entity.identifier):
                try:
                    entity_indicator_id = threatq_manager.get_indicator_id(entity.identifier)
                    objects_to_link[entity_indicator_id] = "indicators"
                except Exception as e:
                    pass
                
            if entity.entity_type == EntityTypes.FILEHASH:    
                try:
                    entity_malware_id = threatq_manager.get_malware_id(entity.identifier)
                    objects_to_link[entity_malware_id] = "malware"
                except Exception as e:
                    pass  
                
            if entity.entity_type == EntityTypes.USER:
                
                try:
                    entity_adversary_id = threatq_manager.get_adversary_id(entity.identifier)
                    objects_to_link[entity_adversary_id] = "adversaries"
                except Exception as e:
                    pass     

            siemplify.LOGGER.info(u"Finished processing entity: {}".format(entity.identifier))
        #Prepare the combinations of objects
        entities_combinations = map(dict, itertools.combinations(objects_to_link.iteritems(), 2))
        
        #Request for linking the objects 
        for entities_combination in entities_combinations:
            link_obj = threatq_manager.link_entities(object_type1=entities_combination.values()[0], object_type2=entities_combination.values()[1], object_id1=entities_combination.keys()[0], object_id2=entities_combination.keys()[1])
            
            #Get object names from Object IDs to know which entities were linked
            for object_id, object_type in entities_combination.items():
                object_name = threatq_manager.get_object_name(object_id=object_id,object_type=object_type)
                if object_name not in successful_entities:
                    successful_entities.append(object_name)
                
            json_results[link_obj.value] = link_obj.to_json()              
        
    except Exception as e:
        output_message = u'Error executing action \"Link Entities\". Reason: {}'.format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
        execution_status = EXECUTION_STATE_FAILED    
            
    if successful_entities and len(siemplify.target_entities) > 1:
        output_message += u"Successfully linked the following entities in ThreatQ: \n{0}".format(u"\n".join([entity for entity in
                                                                                   successful_entities]))
        result_value = True 

        siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    elif len(siemplify.target_entities) > 1 or len(siemplify.target_entities) == 0:
        output_message += u"\nNo entities were linked."
        result_value = False
        
    else:
        output_message += u"\nNo entities were linked. Reason: Only one entity was provided."
        result_value = False        

    for entity in siemplify.target_entities:
        if entity.identifier not in successful_entities:
            failed_entities.append(entity)
    
    if failed_entities and len(successful_entities) > 1:
        output_message += u"\nAction was not able to link the following entities in ThreatQ:\n{0}".format(
            u"\n".join([entity.identifier for entity in
                        failed_entities]))

    siemplify.LOGGER.info('=' * 10 + ' Main - Finished ' + '=' * 10)
    siemplify.LOGGER.info(
        u'Status: {}, Result Value: {}, Output Message: {}'
        .format(execution_status, result_value, output_message)
    )
    siemplify.end(output_message, result_value, execution_status)


if __name__ == '__main__':
    main()
