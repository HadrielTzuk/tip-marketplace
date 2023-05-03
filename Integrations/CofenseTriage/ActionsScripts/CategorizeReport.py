from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CofenseTriageManager import CofenseTriageManager
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    CATEGORIZE_REPORT_ACTION

)
from CofenseTriageExceptions import (
    RecordNotFoundException
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CATEGORIZE_REPORT_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Root", is_mandatory=True, print_value=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Client ID", is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Client Secret", is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool, is_mandatory=True, print_value=True)

    report_id = extract_action_param(siemplify, param_name="Report ID", is_mandatory=True, print_value=True, input_type=str)
    category_name = extract_action_param(siemplify, param_name="Category Name", is_mandatory=True, print_value=True, input_type=str)

    output_message = ""
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    
    try:
        cofensetriage_manager = CofenseTriageManager(api_root=api_root, client_id=client_id, client_secret=client_secret, verify_ssl=verify_ssl)
        category = cofensetriage_manager.get_category_id(category_name)
        
        if category:
            cofensetriage_manager.categorize_report(report_id, category[0].category_id)
            report = cofensetriage_manager.get_report(report_id)
            siemplify.result.add_result_json(report.to_json())
            
            output_message += "Successfully updated category on the the report with ID {} to {} in {}.".format(report_id, category_name, INTEGRATION_NAME)
            
        else:
            output_message += "Action wasn't able to update the category on the report with ID {} to {} in {}. Reason: Category {} was not found.".format(report_id, category_name, INTEGRATION_NAME, category_name)
            result_value = False          
  
    except RecordNotFoundException as e:
        output_message += "Action wasn't able to update the category on the report with ID {} to {} in {}. Reason:\n {}".format(report_id, category_name, CATEGORIZE_REPORT_ACTION, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False    
        
    except Exception as e:
        output_message += 'Error executing action {}. Reason: {}'.format(CATEGORIZE_REPORT_ACTION, e)
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
