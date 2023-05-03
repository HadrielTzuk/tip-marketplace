from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from MicrosoftManager import MicrosoftTeamsManager
import json
from TIPCommon import extract_configuration_param,extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from MicrosoftConstants import (
    INTEGRATION_NAME,
    LIST_TEAMS_ACTION
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_TEAMS_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Client ID", is_mandatory=True, print_value=True)
    secret_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Secret ID", is_mandatory=True, print_value=False)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Tenant", is_mandatory=True, print_value=True)
    token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Refresh Token", is_mandatory=True, print_value=False)
    redirect_url = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Redirect URL", is_mandatory=False, print_value=True)    


    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = {}
    output_message = ""
    
    try:
        
        max_teams_to_return = extract_action_param(siemplify, input_type=int, param_name="Max Teams To Return", print_value=True, is_mandatory=False)

        if max_teams_to_return is not None and max_teams_to_return < 1:
            raise Exception("\"Max Teams To Return\" must be greater than 0.")
                
        mtm = MicrosoftTeamsManager(client_id, secret_id, tenant, token, redirect_url)
        teams = mtm.list_teams(max_teams_to_return=max_teams_to_return) or []
        result_value = json.dumps(teams)
        
        if teams:
            output_message = "Successfully get teams."
        else:
            output_message = "No results were found."
            
        siemplify.result.add_result_json( result_value or {})
        
    except Exception as e:
        output_message = f'Error executing action {LIST_TEAMS_ACTION}. Reason: {e}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        
    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        f"\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()

