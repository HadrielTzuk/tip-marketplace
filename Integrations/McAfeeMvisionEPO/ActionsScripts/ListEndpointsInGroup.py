from SiemplifyAction import SiemplifyAction
from McAfeeMvisionEPOManager import McAfeeMvisionEPOManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import LIST_ENDPOINTS_SCRIPT_NAME, INTEGRATION_NAME, DEFAULT_LIMIT_ENDPOINTS
from exceptions import GroupNotFoundException
from SiemplifyDataModel import EntityTypes


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_ENDPOINTS_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    # Configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client ID',
                                            is_mandatory=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client Secret',
                                                is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=True, input_type=bool)

    scopes = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Scopes',
                                         is_mandatory=True)

    group_name = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Group Name')

    # Parameters
    group_name = extract_action_param(siemplify, param_name='Group Name', is_mandatory=True)
    max_endpoints_to_return = extract_action_param(siemplify, param_name='Max Endpoints to Return', is_mandatory=False, input_type=int, default_value=DEFAULT_LIMIT_ENDPOINTS)

    if max_endpoints_to_return <= 0:
        max_endpoints_to_return = DEFAULT_LIMIT_ENDPOINTS

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ''
    json_results = []
    csv_table = []

    try:
        manager = McAfeeMvisionEPOManager(api_root, client_id, client_secret, scopes, group_name, verify_ssl,
                                            siemplify.LOGGER)

        endpoints_for_group = manager.get_endpoints_for_group(group_name, max_endpoints_to_return)
        
        if endpoints_for_group:
            for endpoint in endpoints_for_group:
                csv_table.append(endpoint.to_table())
                json_results.append(endpoint.to_json()) 
                
            siemplify.result.add_result_json(json_results)  
            siemplify.result.add_data_table(title="Available Endpoints", data_table= construct_csv(csv_table))
            output_message += "Successfully listed endpoints that are a part of {0} group".format(group_name)            
        else:
            output_message += "No endpoints were found in the McAfee Mvision ePO group {0}.".format(group_name) 
            
    except GroupNotFoundException as e:
        output_message += "Action wasn’t able to list endpoints that are a part of {0} group. Reason: Group {0} was not found in McAfee Mvision ePO. Please check for any spelling mistakes. In order to get the list of available groups execute action \"List Groups\"".format(group_name)
        siemplify.LOGGER.error(output_message)
        result_value = False

    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(LIST_ENDPOINTS_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message += "Error executing action List Endpoints In Group. Reason: {0}".format(e)
        result_value = False           

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)

if __name__ == '__main__':
    main()
