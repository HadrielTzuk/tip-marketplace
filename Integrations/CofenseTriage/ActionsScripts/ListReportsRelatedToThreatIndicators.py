
from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CofenseTriageManager import CofenseTriageManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import (
    INTEGRATION_NAME,
    LIST_REPORTS_RELATED_TO_THREAT_IND_ACTION,
    DEFAULT_MAX_REPORTS_TO_RETURN

)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_REPORTS_RELATED_TO_THREAT_IND_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Root", is_mandatory=True, print_value=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Client ID", is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Client Secret", is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool, is_mandatory=True, print_value=True)

    create_case_wall_table  = extract_action_param(siemplify, param_name="Create Case Wall Table", is_mandatory=False, print_value=True, default_value=False, input_type=bool)
    max_reports_to_return = extract_action_param(siemplify, param_name="Max Reports To Return", default_value=DEFAULT_MAX_REPORTS_TO_RETURN, is_mandatory=False, print_value=True, input_type=int)
    
    
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""
    related_reports_json_output = []
    related_entities_case_wall = []
    try:
        
        if max_reports_to_return < 0:
            siemplify.LOGGER.info("Given value for Max Reports To Return parameter is below 0, using default value of {} instead.".format(DEFAULT_MAX_REPORTS_TO_RETURN)) 
            max_reports_to_return = DEFAULT_MAX_REPORTS_TO_RETURN
         
        entities = ','.join([entity.identifier for entity in siemplify.target_entities])
        cofensetriage_manager = CofenseTriageManager(api_root=api_root, client_id=client_id, client_secret=client_secret, verify_ssl=verify_ssl)
        all_related_reports = cofensetriage_manager.get_threat_indicators_id(entities, max_reports_to_return)
        
        if any(all_related_reports):
            for related_report_by_id in all_related_reports:
                for related_reports in related_report_by_id:
                    related_reports_json_output.append(related_reports.to_json())
                    if create_case_wall_table :
                        related_entities_case_wall.append(related_reports.to_table())
            siemplify.result.add_result_json(related_reports_json_output)
            if create_case_wall_table :
                siemplify.result.add_entity_table(
                    'Related Reports',
                    construct_csv(related_entities_case_wall)
                )       
            output_message += "Successfully returned reports related to provided entities from Cofense Triage."
            
        else:
            output_message += "No related reports were found for the provided entities."
            result_value = False
            
    except Exception as e:
        output_message += 'Error executing action {}. Reason: {}'.format(LIST_REPORTS_RELATED_TO_THREAT_IND_ACTION, e)
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