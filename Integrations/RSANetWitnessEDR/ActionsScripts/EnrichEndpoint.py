from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction, ScriptResult
from RSAManager import RSAManager
from RSAExceptions import MachineDoesntExistError
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyDataModel import EntityTypes
from constants import (
    INTEGRATION_NAME,
    ENRICHENDPOINT_ACTION,
    ENRICHMENT_PREFIX
)

SUPPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS,EntityTypes.HOSTNAME]

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICHENDPOINT_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Root")
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Username")
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    # Parameters
    iioc_score_threshold = extract_action_param(siemplify, param_name="IIOC Score Threshold", default_value=50, input_type=int)
    max_iocs_to_return = extract_action_param(siemplify, param_name="Max IOCs To Return", default_value=50, input_type=int)
    include_ioc_information = extract_action_param(siemplify, param_name="Include IOC Information", default_value=False, input_type=bool)
                                                                            
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    successful_entities = []
    failed_entities = []
    output_message = ""
    json_results = {}
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]
    
    if suitable_entities:
        try:
            rsa_manager = RSAManager(api_root=api_root, username=username,
                                     password=password, verify_ssl=verify_ssl)
            
            for entity in suitable_entities:
                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))
                
                try:
                    if entity.entity_type == EntityTypes.ADDRESS:
                        entity_object = rsa_manager.enrich_endpoint(entity_id=entity.identifier, entity_type=entity.entity_type)
                        if include_ioc_information:
                            iocs_object =  rsa_manager.get_endpoint_iocs(entity_id=entity.identifier, entity_type=entity.entity_type, max_iocs_to_return=max_iocs_to_return)
                    else:
                        entity_object = rsa_manager.enrich_endpoint(entity_id=entity.identifier, entity_type=entity.entity_type)
                        if include_ioc_information:
                            iocs_object =  rsa_manager.get_endpoint_iocs(entity_id=entity.identifier, entity_type=entity.entity_type, max_iocs_to_return=max_iocs_to_return)
                    
                    if entity_object:
                        enrichment_data = entity_object.to_enrichment_data(prefix=ENRICHMENT_PREFIX)
                        entity.additional_properties.update(enrichment_data)
                        entity.is_enriched = True
                        object_json = entity_object.to_json()
                        
                        if iioc_score_threshold and int(entity_object.iioc_score) > iioc_score_threshold:
                            entity.is_suspicious = True
                        
                        #If both objects were requested, JSONs are combined
                        if include_ioc_information and iocs_object:
                            object_json = {**entity_object.to_json(), **iocs_object}
               
                        # JSON result
                        json_results[entity.identifier] = object_json
                        successful_entities.append(entity)
                    else:
                        failed_entities.append(entity)
    
                    siemplify.LOGGER.info("Finished processing entity {}".format(entity.identifier))        
                    
                except MachineDoesntExistError as e:
                    failed_entities.append(entity)
                    siemplify.LOGGER.info("Failed processing entity {}. Reason: {}".format(entity.identifier, e))
                    pass

        except Exception as e:
            output_message = 'Error executing action {}. Reason: {}'.format(ENRICHENDPOINT_ACTION, e)
            siemplify.LOGGER.error(output_message)
            siemplify.LOGGER.exception(e)
            status = EXECUTION_STATE_FAILED
            result_value = False

    if successful_entities:
        siemplify.update_entities(successful_entities)
        siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
        output_message = "Successfully enriched the following endpoints from RSA Netwitness EDR: {}".format("\n".join([entity.identifier for entity in successful_entities]))
        siemplify.LOGGER.info("Successfully enriched the following endpoints from RSA Netwitness EDR: {}".format("\n".join([entity.identifier for entity in successful_entities])))
        
    if failed_entities :
        output_message += "Action was not able to enrich the following endpoints from RSA Netwitness EDR: {}".format("\n".join([entity.identifier for entity in failed_entities]))
        siemplify.LOGGER.info("Action was not able to enrich the following endpoints from RSA Netwitness EDR: {}".format("\n".join([entity.identifier for entity in failed_entities])))
        
    if not successful_entities:
        output_message = "No entities were enriched."
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
