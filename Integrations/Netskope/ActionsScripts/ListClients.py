from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from NetskopeManager import NetskopeManager
import json
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv, dict_to_flat
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

INTEGRATION_NAME = "Netskope"
LISTCLIENTS_SCRIPT_NAME = '{} - ListClients'.format(INTEGRATION_NAME)
CSV_TABLE_NAME = "Netskope - Clients"
DEFAULT_LIMIT = 25

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LISTCLIENTS_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Key',
                                           is_mandatory=True)    
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                           is_mandatory=True, default_value=True, input_type=bool)

    # Parameters
    query = extract_action_param(siemplify, param_name='Query', is_mandatory=False)
    limit = extract_action_param(siemplify, param_name='Limit', is_mandatory=False, default_value=DEFAULT_LIMIT, input_type=int)
    
    if limit <= 0:
        siemplify.LOGGER.info('The limit is less than zero, using default limit {} instead.'.format(DEFAULT_LIMIT))
        limit = DEFAULT_LIMIT
       
    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_FAILED
    json_results = []
    output_clients = ""
    csv_table = []
    
    try: 
        netskope_manager = NetskopeManager(server_address, api_key, verify_ssl=verify_ssl)
        clients = netskope_manager.get_clients(query=query,limit=limit) or []

        output_message = "Found {} clients".format(len(clients))
        
        for client in clients:
            csv_table.append(client.to_table_data())
            json_results.append(client.to_json()) 
                
        if clients:
            siemplify.result.add_result_json(json_results)  
            siemplify.result.add_data_table(title=CSV_TABLE_NAME, data_table= construct_csv(csv_table))        
        
        output_clients = json.dumps(json_results)
        status = EXECUTION_STATE_COMPLETED
        
    except Exception as e:
        output_message = "Error executing action \"ListClients\". Reason: {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
   
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, output_clients, status)
        
    
if __name__ == "__main__":
    main()