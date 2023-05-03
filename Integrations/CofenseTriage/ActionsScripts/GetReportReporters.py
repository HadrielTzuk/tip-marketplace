from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CofenseTriageManager import CofenseTriageManager
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    GET_REPORT_REPORTERS_ACTION

)
from CofenseTriageExceptions import (
    RecordNotFoundException
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_REPORT_REPORTERS_ACTION
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

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""
    report_reporters = []
    
    try:
        cofensetriage_manager = CofenseTriageManager(api_root=api_root, client_id=client_id, client_secret=client_secret, verify_ssl=verify_ssl)
        report = cofensetriage_manager.get_report_reporters(report_id)
        
        if report.to_json():
            siemplify.result.add_result_json(report.to_json())

            report_reporters.append(report.to_table())            
                        
            siemplify.result.add_entity_table(
                'Report {} Reporters'.format(report_id),
                construct_csv(report_reporters)
            )

            output_message += "Successfully returned related reporters to the report with ID {} in {}.".format(report_id, INTEGRATION_NAME)
        else:
            output_message += "No related reporters were found to the report with ID {} in {}.".format(report_id, INTEGRATION_NAME)

    except RecordNotFoundException as e:
        output_message += "Action wasn't able to return related reporters to the report with ID {} in {}. Reason:\n {}".format(report_id, GET_REPORT_REPORTERS_ACTION, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False    
        
    except Exception as e:
        output_message += 'Error executing action {}. Reason: {}'.format(GET_REPORT_REPORTERS_ACTION, e)
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
