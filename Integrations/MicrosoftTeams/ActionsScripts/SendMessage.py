from MicrosoftManager import MicrosoftTeamsManager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param,extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from MicrosoftConstants import (
    INTEGRATION_NAME,
    SEND_MESSAGE_ACTION
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SEND_MESSAGE_ACTION
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

    team_name = extract_action_param(siemplify, param_name="Team Name", print_value=True, is_mandatory=True)
    channel_name = extract_action_param(siemplify, param_name="Channel Name", print_value=True, is_mandatory=True)
    message = extract_action_param(siemplify, param_name="Message", print_value=True, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""
    
    try:
        mtm = MicrosoftTeamsManager(client_id, secret_id, tenant, token, redirect_url)
        message_res = mtm.send_message(channel_name, team_name, message) or []
        
        if message_res:
            output_message = f"Successfully send message to channel {channel_name} in team {team_name}."
            siemplify.result.add_result_json(message_res)
        else:
            output_message = "{message} message NOT delivered to channel {channel_name}."
            result_value = False       

    except Exception as e:
        output_message = f'Error executing action {SEND_MESSAGE_ACTION}. Reason: {e}'
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