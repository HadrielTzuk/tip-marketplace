from SiemplifyAction import SiemplifyAction
from McAfeeMvisionEPOManager import McAfeeMvisionEPOManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import LIST_GROUPS_SCRIPT_NAME, INTEGRATION_NAME, DEFAULT_LIMIT_GROUPS
from exceptions import TagNotFoundException, EndpointNotFoundException
from SiemplifyDataModel import EntityTypes


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_GROUPS_SCRIPT_NAME
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
    max_groups_to_return = extract_action_param(siemplify, param_name='Max Groups to Return', is_mandatory=False, input_type=int, default_value=DEFAULT_LIMIT_GROUPS)

    if max_groups_to_return <= 0:
        max_groups_to_return = DEFAULT_LIMIT_GROUPS

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ''
    json_results = []
    csv_table = []

    try:
        manager = McAfeeMvisionEPOManager(api_root, client_id, client_secret, scopes, group_name, verify_ssl,
                                            siemplify.LOGGER)
        groups = manager.list_groups(max_groups_to_return)
        if groups:
            for group in groups:
                csv_table.append(group.to_table())
                json_results.append(group.to_json()) 
            
            siemplify.result.add_result_json(json_results)  
            siemplify.result.add_data_table(title="Available Groups", data_table= construct_csv(csv_table))
            output_message += "Successfully listed available groups in McAfee Mvision ePO."
        
        else:
            result_value = False
            output_message += "Action wasn’t able to list groups available in McAfee Mvision ePO."
                    
    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(LIST_GROUPS_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message += "Error executing action List Groups. Reason: {0}".format(e)
        result_value = False           

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)

if __name__ == '__main__':
    main()
