from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from CofenseTriageManager import CofenseTriageManager
from TIPCommon import extract_configuration_param, construct_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyDataModel import EntityTypes
from UtilsManager import get_entity_original_identifier, is_valid_email
from constants import (
    INTEGRATION_NAME,
    GET_THREAT_INDICATOR_DETAILS_ACTION,
    THREAT_LEVELS

)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_THREAT_INDICATOR_DETAILS_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Root", is_mandatory=True, print_value=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Client ID", is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Client Secret", is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool, is_mandatory=True, print_value=True)


    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    json_results = {}
    entities_to_update = []
    failed_entities = []   
    output_message = ""
    ti_details_table = []
    
    try:
        cofensetriage_manager = CofenseTriageManager(api_root=api_root,client_id=client_id, client_secret=client_secret, verify_ssl=verify_ssl)
        for entity in siemplify.target_entities:
            siemplify.LOGGER.info("Started processing entity:{}".format(entity.identifier))
            try:
                entity_identifier = entity.identifier

                if entity.entity_type == EntityTypes.USER and is_valid_email(get_entity_original_identifier(entity)):
                    entity_identifier = f"From:{entity.identifier},To:{entity.identifier}"

                if entity.entity_type == EntityTypes.EMAILMESSAGE:
                    entity_identifier = f"Subject:{entity.identifier}"

                entity_object = cofensetriage_manager.get_threat_indicator_details(entity_identifier)
                
                if not entity_object.to_json():
                    siemplify.LOGGER.info("No threat indicators were found for entity: {}".format(entity.identifier))
                    failed_entities.append(entity)
                    continue
                
                if entity_object.ti_threat_level in THREAT_LEVELS:
                    entity.is_suspicious = True
                    
                json_results[entity.identifier] = entity_object.to_json()
                entities_to_update.append(entity)
                entity.is_enriched = True
                entity.additional_properties.update(entity_object.as_enrichment_data())
                ti_details_table.append(entity_object.to_table())

            except Exception as e:
                output_message += "Unable to enrich entity: {} \n".format(entity.identifier)
                failed_entities.append(entity)
                siemplify.LOGGER.error("Failed processing entity:{}".format(entity.identifier))
                siemplify.LOGGER.exception(e)
            
            siemplify.LOGGER.info("Finished processing entity:{}".format(entity.identifier))

    except Exception as e:
        output_message += 'Error executing action {}. Reason: {}'.format(GET_THREAT_INDICATOR_DETAILS_ACTION, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
            
    if len(siemplify.target_entities) == len(failed_entities):
        output_message += "No threat indicator information about the entities was found."
        result_value = False
    
    else:
        if entities_to_update:
            siemplify.update_entities(entities_to_update)
            output_message += "Successfully returned threat indicator details about the following entities using {}:\n{}".format(INTEGRATION_NAME,"\n".join([entity.identifier for entity in
                                                                                entities_to_update]))
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            siemplify.result.add_entity_table(
                 'Threat Indicator Table',
                 construct_csv(ti_details_table)
            )
            
        if failed_entities:
            output_message += "\nAction wasn't able to return threat indicator details about the following entities using {}:\n{}".format(INTEGRATION_NAME,
            "\n".join([entity.identifier for entity in
                        failed_entities]))        


    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
