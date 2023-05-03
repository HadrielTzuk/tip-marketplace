from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from NetskopeManager import NetskopeManager
import json
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv, dict_to_flat
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

INTEGRATION_NAME = "Netskope"
LISTALERTS_SCRIPT_NAME = '{} - ListAlerts'.format(INTEGRATION_NAME)
CSV_TABLE_NAME = "Netskope - Alerts"
DEFAULT_LIMIT = 100

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LISTALERTS_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Key',
                                           is_mandatory=True)    
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                           is_mandatory=True, default_value=True, input_type=bool)

    # Parameters
    query = extract_action_param(siemplify, param_name='Query', is_mandatory=False)
    alert_type = extract_action_param(siemplify, param_name='Type', is_mandatory=False)
    time_period = extract_action_param(siemplify, param_name='Time Period', is_mandatory=False)
    start_time = extract_action_param(siemplify, param_name='Start Time', is_mandatory=False)    
    end_time = extract_action_param(siemplify, param_name='End Time', is_mandatory=False)   
    limit = extract_action_param(siemplify, param_name='Limit', is_mandatory=False, default_value=DEFAULT_LIMIT, input_type=int)
    acked = extract_action_param(siemplify, param_name='Is Acknowledged', is_mandatory=False, default_value=False, input_type=bool)       

    if limit <= 0:
        siemplify.LOGGER.info('The limit is less than zero, using default limit {} instead.'.format(DEFAULT_LIMIT))
        limit = DEFAULT_LIMIT     
    
    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_FAILED
    json_results = []
    output_alerts = ""
    
    try: 
        netskope_manager = NetskopeManager(server_address, api_key, verify_ssl=verify_ssl)
        alerts = netskope_manager.get_alerts(
            query=query,
            alert_type=alert_type,
            timeperiod=time_period,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            acked=acked
        )
        
        output_message = "Found {} alerts".format(len(alerts))
        if alerts:
            json_results = alerts
            flat_alerts = list(map(dict_to_flat, alerts))
            csv_output = construct_csv(flat_alerts)
            siemplify.result.add_data_table(CSV_TABLE_NAME, csv_output)

        # add json
        siemplify.result.add_result_json(json.dumps(json_results))
        output_alerts = json.dumps(alerts)
        status = EXECUTION_STATE_COMPLETED    
                
    except Exception as e:
        output_message = "Error executing action \"ListAlerts\". Reason: {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)  

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, output_alerts, status)

if __name__ == "__main__":
    main()