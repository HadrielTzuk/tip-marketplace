import datetime

from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS, \
    EXECUTION_STATE_TIMEDOUT

from MicrosoftManager import MicrosoftTeamsManager
from MicrosoftExceptions import (
    MicrosoftTeamsManagerError,
    MicrosoftTeamsMessageNotFoundError,
    MicrosoftTeamsTeamNotFoundError,
    MicrosoftTeamsChannelNotFoundError
)
from MicrosoftConstants import (
    INTEGRATION_NAME,
    WAIT_REPLY_SCRIPT,
    WAIT_TILL_TIMEOUT,
    CHECK_FIRST_REPLY,
    TIMEOUT_BUFFER_IN_SECONDS
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = WAIT_REPLY_SCRIPT


    siemplify.LOGGER.info('=' * 20 + ' Main - Param Init ' + '=' * 20)

    client_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Client ID',
        print_value=False,
        is_mandatory=True
    )

    client_secret = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Secret ID',
        print_value=False,
        is_mandatory=True
    )

    tenant = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Tenant',
        print_value=False,
        is_mandatory=True
    )

    refresh_token = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Refresh Token',
        print_value=False,
        is_mandatory=True
    )

    redirect_url = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Redirect URL',
        print_value=True,
        is_mandatory=False
    )

    team_name = extract_action_param(
        siemplify,
        param_name='Team Name',
        print_value=True,
        is_mandatory=True
    )

    channel_name = extract_action_param(
        siemplify,
        param_name='Channel Name',
        print_value=True,
        is_mandatory=True
    )

    message_id = extract_action_param(
        siemplify,
        param_name='Message ID',
        print_value=True,
        input_type=int,
        is_mandatory=True
    )

    expected_reply = extract_action_param(
        siemplify,
        param_name='Expected Reply',
        print_value=True,
        is_mandatory=True
    )

    wait_method = extract_action_param(
        siemplify,
        param_name='Wait Method',
        print_value=True,
        is_mandatory=False
    )

    siemplify.LOGGER.info('=' * 20 + ' Main - Started ' + '=' * 20)

    try:
        ms_teams_manager = MicrosoftTeamsManager(
            client_id=client_id,
            client_secret=client_secret,
            tenant=tenant,
            refresh_token=refresh_token,
            redirect_url=redirect_url
        )

        if siemplify.execution_deadline_unix_time_ms - unix_now()  <= TIMEOUT_BUFFER_IN_SECONDS * 1000:
            timeout_datetime = convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)
            siemplify.LOGGER.info(
                'Action will work till the timeout {}. Buffer time is {} seconds.'
                .format(
                    timeout_datetime - datetime.timedelta(seconds=TIMEOUT_BUFFER_IN_SECONDS),
                    TIMEOUT_BUFFER_IN_SECONDS
                )
            )
            output_message = 'Expected reply {} was not seen to message with ID {} in channel {} of team {}'\
                .format(expected_reply, message_id, channel_name, team_name)
            result = False
            status = EXECUTION_STATE_TIMEDOUT
            siemplify.end(output_message, result, status)

        replies = ms_teams_manager.get_message_replies(
            team_name=team_name,
            channel_name=channel_name,
            message_id=message_id
        )

        siemplify.LOGGER.info('Found {} replies'.format(len(replies)))

        if wait_method == CHECK_FIRST_REPLY:
            if not replies or replies and expected_reply != replies[0].get('body', {}).get('content'):
                output_message = 'Expected reply {} was not seen to message with ID {} in channel {} of team {}'\
                    .format(expected_reply, message_id, channel_name, team_name)
                result = False
            else:
                output_message = 'Message with ID {} in channel {} of team {} has expected reply {}!'\
                    .format(message_id, channel_name, team_name, expected_reply)
                result = True

            status = EXECUTION_STATE_COMPLETED

        elif wait_method == WAIT_TILL_TIMEOUT:
            output_message = 'Message with expected reply {} not found yet'.format(expected_reply)
            result = False
            status = EXECUTION_STATE_INPROGRESS

            for reply in replies:
                if expected_reply in reply.get('body', {}).get('content'):
                    output_message = 'Message with ID {} in channel {} of team {} has expected reply {}!'.format(
                        message_id, channel_name, team_name, expected_reply
                    )
                    result = True
                    status = EXECUTION_STATE_COMPLETED
        else:
            raise MicrosoftTeamsManagerError('Unknown wait method {}'.format(wait_method))

    except MicrosoftTeamsMessageNotFoundError as e:
        output_message = 'Error executing action Wait for Reply. ' \
            'Reason: Message with ID {} wasn\'t found in channel {} of team {}'\
            .format(message_id, channel_name, team_name)
        result = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    except MicrosoftTeamsChannelNotFoundError as e:
        output_message = 'Error executing action Wait for Reply. Reason: Channel {} wasn\'t found in team {}.'\
            .format(channel_name, team_name)
        result = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    except MicrosoftTeamsTeamNotFoundError as e:
        output_message = 'Error executing action Wait for Reply. Reason: Team {} wasn\'t found.'.format(team_name)
        result = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    except Exception as e:
        output_message = 'Error executing action Wait for Reply. Reason: {}'.format(e)
        result = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
