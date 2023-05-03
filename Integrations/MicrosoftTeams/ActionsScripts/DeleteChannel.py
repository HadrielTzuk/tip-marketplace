from MicrosoftManager import MicrosoftTeamsManager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from MicrosoftConstants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, DELETE_CHANNEL_ACTION
from MicrosoftExceptions import MicrosoftTeamsTeamNotFoundError


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = DELETE_CHANNEL_ACTION
    siemplify.LOGGER.info(f"----------------- Main - Param Init -----------------")

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            is_mandatory=True, print_value=True)
    secret_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Secret ID",
                                            is_mandatory=True, print_value=False)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Tenant",
                                         is_mandatory=True, print_value=True)
    token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Refresh Token",
                                        is_mandatory=True, print_value=False)
    redirect_url = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Redirect URL",
                                               is_mandatory=False, print_value=True)

    team_name = extract_action_param(siemplify, param_name="Team Name", is_mandatory=True, print_value=True)
    channel_name = extract_action_param(siemplify, param_name="Channel Name", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        manager = MicrosoftTeamsManager(client_id=client_id, client_secret=secret_id, tenant=tenant,
                                        refresh_token=token, redirect_url=redirect_url)
        try:
            team_id = manager.get_team_id(team_name=team_name)
        except MicrosoftTeamsTeamNotFoundError:
            raise Exception(f"team with name {team_name} was not found in {INTEGRATION_DISPLAY_NAME}.")

        try:
            channel_id = manager.get_channel_id(team_id=team_id, channel_name=channel_name)
        except MicrosoftTeamsTeamNotFoundError:
            output_message = f"Channel \"{channel_name}\" already didn't exist in team \"{team_name}\" in " \
                             f"{INTEGRATION_DISPLAY_NAME}."
        else:
            manager.delete_channel(team_id, channel_id)
            output_message = f"Successfully deleted channel \"{channel_name}\" in team \"{team_name}\" in " \
                             f"{INTEGRATION_DISPLAY_NAME}."

    except Exception as e:
        output_message = f"Error executing action {DELETE_CHANNEL_ACTION}. Reason: {e}"
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(f"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
