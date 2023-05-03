import sys
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from ZohoDeskManager import ZohoDeskManager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from constants import (
    INTEGRATION_NAME,
    INTEGRATION_DISPLAY_NAME,
    ADD_COMMENT_TO_TICKET_SCRIPT_NAME,
    PUBLIC_VISIBILITY,
    CONTENT_TYPE_MAPPING,
    MAX_LIMIT
)


def add_comment(manager, ticket_id, visibility, type, text, wait_for_reply):
    """
    Add comment to ticket
    :param manager {ZohoDeskManager} ZohoDeskManager instance
    :param ticket_id {str} Ticket ID
    :param visibility {str} Specifies visibility (public/private)
    :param type {str} Type of the comment (plain text/html)
    :param text {str} Content of the comment
    :param wait_for_reply {bool} Specifies if reply should be fetched
    :return: {tuple} status, result_value, output_message
    """
    manager.add_comment(ticket_id=ticket_id, is_public=True if visibility == PUBLIC_VISIBILITY else False,
                        content_type=CONTENT_TYPE_MAPPING.get(type), content=text)
    result_value = True

    if wait_for_reply:
        status = EXECUTION_STATE_INPROGRESS
        output_message = "Waiting for a reply..."
    else:
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully added comment \"{text}\" to ticket {ticket_id} " \
                         f"in {INTEGRATION_DISPLAY_NAME}."

    return status, result_value, output_message


def get_reply(siemplify, manager, ticket_id, text):
    """
    Get comment reply
    :param siemplify: SiemplifyAction object.
    :param manager {ZohoDeskManager} ZohoDeskManager instance
    :param ticket_id {str} Ticket ID
    :param text {str} Content of the comment
    :return: {tuple} status, result_value, output_message
    """
    comments = manager.get_ticket_comments(ticket_id=ticket_id, limit=MAX_LIMIT)
    indices = [index for (index, comment) in enumerate(comments) if comment.content == text]
    comment_index = max(indices) + 1 if indices else None
    replies = comments[comment_index:] if comment_index else []
    result_value = True

    if replies:
        first_reply = replies[0]
        siemplify.result.add_result_json(first_reply.to_json())
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully added comment \"{text}\" to ticket {ticket_id} " \
                         f"in {INTEGRATION_DISPLAY_NAME}."
    else:
        status = EXECUTION_STATE_INPROGRESS
        output_message = "Waiting for a reply..."

    return status, result_value, output_message


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_COMMENT_TO_TICKET_SCRIPT_NAME
    mode = "Main" if is_first_run else "QueryState"
    siemplify.LOGGER.info(f"----------------- {mode} - Param Init -----------------")

    # Configuration.
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client Secret",
                                                is_mandatory=True, remove_whitespaces=False)
    refresh_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Refresh Token",
                                                is_mandatory=False, remove_whitespaces=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)
    # Parameters
    ticket_id = extract_action_param(siemplify, param_name="Ticket ID", is_mandatory=True, print_value=True)
    visibility = extract_action_param(siemplify, param_name="Visibility", print_value=True)
    type = extract_action_param(siemplify, param_name="Type", print_value=True)
    text = extract_action_param(siemplify, param_name="Text", is_mandatory=True, print_value=True)
    wait_for_reply = extract_action_param(siemplify, param_name="Wait For Reply", is_mandatory=True, input_type=bool,
                                          print_value=True)

    siemplify.LOGGER.info(f"----------------- {mode} - Started -----------------")

    try:
        manager = ZohoDeskManager(api_root=api_root, client_id=client_id, client_secret=client_secret,
                                  refresh_token=refresh_token, verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)

        if is_first_run:
            status, result_value, output_message = add_comment(manager, ticket_id, visibility, type, text,
                                                               wait_for_reply)
        else:
            status, result_value, output_message = get_reply(siemplify, manager, ticket_id, text)

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {ADD_COMMENT_TO_TICKET_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{ADD_COMMENT_TO_TICKET_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info(f"----------------- {mode} - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)
