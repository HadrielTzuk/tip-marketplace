from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import (
    extract_configuration_param,
    extract_action_param,
    construct_csv,
    convert_list_to_comma_string,
    convert_comma_separated_to_list
)
from SiemplifyUtils import convert_dict_to_json_result_dict
from QualysVMManager import QualysVMManager
from constants import POSSIBLE_STATUSES, CRITICAL_SEVERITY, USER_DETECTION_SEVERITY_MAP, INTEGRATION_NAME, LIST_ENDPOINT_DETECTIONS_SCRIPT_NAME, ENRICHMENT_PREFIX, MAX_DETECTIONS_TO_FETCH
from SiemplifyDataModel import EntityTypes

SUPPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_ENDPOINT_DETECTIONS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True, print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    create_insight = extract_action_param(
        siemplify, param_name="Create Insight", is_mandatory=False, default_value=True, input_type=bool, print_value=True
    )
    ingest_ignored_detections = extract_action_param(
        siemplify, param_name="Ingest Ignored Detections", is_mandatory=False, default_value=False, input_type=bool, print_value=True
    )
    ingest_disabled_detections = extract_action_param(
        siemplify, param_name="Ingest Disabled Detections", is_mandatory=False, default_value=False, input_type=bool, print_value=True
    )    
    lowest_severity_to_fetch = extract_action_param(siemplify, param_name="Lowest Severity To Fetch", default_value="Medium", is_mandatory=False, input_type=str, print_value=True
    )    
    status_filter = extract_action_param(siemplify, param_name="Status Filter", default_value="New,Active,Re-Opened", is_mandatory=False, input_type=str, print_value=True
    )      
    statuses = convert_comma_separated_to_list(status_filter)
      
    limit = extract_action_param(siemplify, param_name="Max Detections To Return", is_mandatory=False, default_value=50, input_type=int, print_value=True
    )        
    
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result = True
    ip_address = None
    
    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    failed_entities = []
    endpoints_not_found = []
    json_results = {}
    message = ""
    output_message = ""
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        if limit <= 0 or limit > MAX_DETECTIONS_TO_FETCH:
            siemplify.LOGGER.error(f"Given value of {limit} for parameter \"Max Detections To Return\" must be between 1 and 200.")
            raise Exception(f"Given value of {limit} for parameter \"Max Detections To Return\" must be between 1 and 200.")
        
        lowest_severity_to_fetch = USER_DETECTION_SEVERITY_MAP.get(lowest_severity_to_fetch)
        if lowest_severity_to_fetch == CRITICAL_SEVERITY:
            severities = CRITICAL_SEVERITY
        else:
            severities = f"{lowest_severity_to_fetch}-5"
            
        for status_filter in statuses:
            if status_filter.title() not in POSSIBLE_STATUSES:
                siemplify.LOGGER.error(f"Invalid value provided for the parameter \"Status Filter\": {status_filter}. Possible values: new, open, reopened, fixed.")
                raise Exception(f"Invalid value provided for the parameter \"Status Filter\": {status_filter}. Possible values: new, open, re-opened, fixed.")          
                
        statuses = [status.title() for status in statuses]    
        statuses = convert_list_to_comma_string(statuses)
            
        qualys_manager = QualysVMManager(api_root, username, password, verify_ssl)
        qualys_manager.test_connectivity()
        for entity in suitable_entities:
            siemplify.LOGGER.info("\nStarted processing entity: {}".format(entity.identifier))
            try:
                if entity.entity_type == EntityTypes.HOSTNAME:
                    ip_address = qualys_manager.find_hostname_ip(hostname=entity.identifier)
                else:
                    ip_address = entity.identifier
                if ip_address is None:
                    siemplify.LOGGER.info(f"Successfully processed entity {entity.identifier} but no details were found in {INTEGRATION_NAME}.")
                    endpoints_not_found.append(entity)       
                    continue
                try:
                    detection_quids = qualys_manager.get_detection_quid(ip_address=ip_address, status=statuses, severities=severities, include_ignored=ingest_ignored_detections, include_disabled=ingest_disabled_detections)
                except Exception as e:
                    endpoints_not_found.append(entity) 
                    continue
            
                detection_quids = list(set(detection_quids))
                detection_quids = detection_quids[:limit] if limit else detection_quids
                detection_quids = ",".join(detection_quids)
                if len(detection_quids) > 0:
                    detection_details = qualys_manager.get_detection_details(detection_quids=detection_quids)
                    json_results[entity.identifier] = [detection.to_json() for detection in detection_details]
                    
                    #Create Data Table
                    siemplify.result.add_data_table(
                    entity.identifier,
                    data_table=construct_csv([detection_detail.to_table() for detection_detail in detection_details]))
                    
                    if create_insight:
                        #Create Insight
                        for detection_detail in detection_details:
                            message = message + detection_detail.as_insight()
                            
                        siemplify.add_entity_insight(entity, message=message,
                                                triggered_by=INTEGRATION_NAME)
                    
                    siemplify.LOGGER.info(f"Successfully processed entity {entity.identifier} and fetched details.")
                    successful_entities.append(entity)
                else:
                    siemplify.LOGGER.info(f"Successfully processed entity {entity.identifier} but no details were found in {INTEGRATION_NAME}.")
                    failed_entities.append(entity)
            except Exception as e:
                # An error occurred - skip entity and continue
                failed_entities.append(entity)
                siemplify.LOGGER.error("An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)
        
        siemplify.LOGGER.info("Finished processing entity {}\n".format(entity.identifier))

        if successful_entities:
            entities_names = [entity.identifier for entity in successful_entities]
            output_message = "Successfully listed detections related to the following endpoints in {}: \n{}".format(INTEGRATION_NAME,
                        "\n".join([entity.identifier for entity in successful_entities]))         
            
            siemplify.update_entities(successful_entities)
            
            if failed_entities:
                output_message += f"\nNo vulnerabilities were found for the following endpoints: " \
                                f"{', '.join([entity.identifier for entity in failed_entities])}"            

            if endpoints_not_found:
                output_message += f"\nAction wasn't able to find the following endpoints in {INTEGRATION_NAME}: " \
                                f"{', '.join([entity.identifier for entity in endpoints_not_found])}"     
            
        elif endpoints_not_found and failed_entities:
            if failed_entities:
                output_message += f"\nNo vulnerabilities were found for the following endpoints: " \
                                f"{', '.join([entity.identifier for entity in failed_entities])}"            

            if endpoints_not_found:
                output_message += f"\nAction wasn't able to find the following endpoints in {INTEGRATION_NAME}: " \
                                f"{', '.join([entity.identifier for entity in endpoints_not_found])}"     
                        
        else:
            result = False
            output_message = "No vulnerabilities were found for the provided endpoints."
    
        if json_results:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {LIST_ENDPOINT_DETECTIONS_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{LIST_ENDPOINT_DETECTIONS_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result, status)

if __name__ == '__main__':
    main()
