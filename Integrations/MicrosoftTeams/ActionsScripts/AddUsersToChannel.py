from MicrosoftManager import MicrosoftTeamsManager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from MicrosoftConstants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, ADD_USERS_TO_CHANNEL_ACTION, \
    PRIVATE_MEMBERSHIP_TYPE
from MicrosoftExceptions import MicrosoftTeamsTeamNotFoundError, MicrosoftTeamsChannelNotFoundError
from SiemplifyDataModel import EntityTypes


SUPPORTED_ENTITY_TYPES = [EntityTypes.USER]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_USERS_TO_CHANNEL_ACTION
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
    output_message = ""
    successful_entities = []
    failed_entities = []
    not_found_entities = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        manager = MicrosoftTeamsManager(client_id=client_id, client_secret=secret_id, tenant=tenant,
                                        refresh_token=token, redirect_url=redirect_url)
        try:
            team_id = manager.get_team_id(team_name=team_name)
        except MicrosoftTeamsTeamNotFoundError:
            raise Exception(f"team with name {team_name} was not found in {INTEGRATION_DISPLAY_NAME}.")

        try:
            channel = manager.get_channel_by_channel_name(team_id, channel_name)

            if channel.get("membershipType") != PRIVATE_MEMBERSHIP_TYPE:
                raise Exception(f"channel with name {channel_name} is not private.")

        except MicrosoftTeamsChannelNotFoundError:
            raise Exception(f"channel with name {channel_name} was not found in {INTEGRATION_DISPLAY_NAME}.")

        users = {}

        for item in manager.list_users():
            users[item.get("displayName")] = item.get("id")
            users[item.get("mail")] = item.get("id")

        for entity in suitable_entities:
            siemplify.LOGGER.info("\nStarted processing entity: {}".format(entity.identifier))

            if entity.identifier in users.keys():
                try:
                    manager.add_user_to_channel(team_id, channel.get("id"), users.get(entity.identifier))
                    successful_entities.append(entity)
                except Exception as e:
                    siemplify.LOGGER.error(f"Failed processing entities: {entity.identifier}: Error is: {e}")
                    failed_entities.append(entity)
            else:
                siemplify.LOGGER.info(f"User not found: {entity.identifier}")
                not_found_entities.append(entity)

            siemplify.LOGGER.info("Finished processing entity {}\n".format(entity.identifier))

        if successful_entities:
            output_message = "Successfully added the following users to the channel \"{}\" from team \"{}\" in {}: \n{}" \
                .format(channel_name, team_name, INTEGRATION_DISPLAY_NAME,
                        "\n".join([entity.identifier for entity in successful_entities]))

        if not_found_entities:
            output_message += "\nAction wasn't able to find the following users in {}: \n{}" \
                .format(INTEGRATION_DISPLAY_NAME, "\n".join([entity.identifier for entity in not_found_entities]))

        if failed_entities:
            output_message += "\nAction wasn't able to add the following users to the channel \"{}\" from team \"{}\" " \
                              "in {}: \n{}. \nMake sure that users are a part of the team \"{}\"."\
                .format(channel_name, team_name, INTEGRATION_DISPLAY_NAME,
                        "\n".join([entity.identifier for entity in failed_entities]), team_name)

        if not successful_entities:
            result_value = False

            if len(not_found_entities) == len(suitable_entities):
                output_message = f"None of the provided users were found in {INTEGRATION_DISPLAY_NAME}."
            elif len(failed_entities) == len(suitable_entities):
                output_message = f"Action wasn't able to add provided users to the channel \"{channel_name}\" from " \
                                 f"team \"{team_name}\" in {INTEGRATION_DISPLAY_NAME}. Make sure that users are a " \
                                 f"part of the team \"{team_name}\""

    except Exception as e:
        output_message = f"Error executing action {ADD_USERS_TO_CHANNEL_ACTION}. Reason: {e}"
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(f"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
