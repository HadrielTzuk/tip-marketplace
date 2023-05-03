from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from NetskopeManager import NetskopeManager
import json
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv, dict_to_flat
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

INTEGRATION_NAME = "Netskope"
LISTQUARANTINEDFILES_SCRIPT_NAME = '{} - ListQuarantinedFiles'.format(INTEGRATION_NAME)
CSV_TABLE_NAME = "Netskope - Quarantined Files"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LISTQUARANTINEDFILES_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Key',
                                           is_mandatory=True)    
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                           is_mandatory=True, default_value=True, input_type=bool)

    # Parameters
    start_time = extract_action_param(siemplify, param_name='Start Time', is_mandatory=False)    
    end_time = extract_action_param(siemplify, param_name='End Time', is_mandatory=False)   
  
    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_FAILED
    json_results = []
    output_files = ""

    try: 
        netskope_manager = NetskopeManager(server_address, api_key, verify_ssl=verify_ssl)
        files = netskope_manager.get_quarantined_files(start_time=start_time, end_time=end_time)

        output_message = "Found {} quarantined files".format(len(files))

        if files:
            json_results = files
            flat_files = list(map(dict_to_flat, files))
            csv_output = construct_csv(flat_files)
            siemplify.result.add_data_table(CSV_TABLE_NAME, csv_output)

        # add json
        siemplify.result.add_result_json(json.dumps(json_results))
        output_files = json.dumps(files)
        status = EXECUTION_STATE_COMPLETED
                 
    except Exception as e:
        output_message = "Error executing action \"ListQuarantinedFiles\". Reason: {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)    

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, output_files, status)
                
if __name__ == "__main__":
    main()