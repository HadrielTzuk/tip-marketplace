from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ZendeskManager import ZendeskManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param


INTEGRATION_NAME = u"Zendesk"
ADD_COMMENT_TO_TICKET = u"Add Comment To Ticket"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_COMMENT_TO_TICKET
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")
    
    user_email = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name=u"User Email Address", is_mandatory=True, print_value=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name=u"Api Token", print_value=False, is_mandatory=True)
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name=u"Server Address", is_mandatory=True, print_value=True)

    ticket_id = extract_action_param(siemplify, param_name=u"Ticket ID", is_mandatory=True, print_value=True, input_type=unicode)
    comment_body = extract_action_param(siemplify, param_name=u"Comment Body", is_mandatory=True, print_value=True, input_type=unicode)
    author_name = extract_action_param(siemplify, param_name=u"Author Name", is_mandatory=False, print_value=True, input_type=unicode)
    is_internal_note = extract_action_param(siemplify, param_name=u"Internal Note", is_mandatory=True, print_value=True, input_type=bool)  
    is_internal_note = not is_internal_note
  
    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")    
    status = EXECUTION_STATE_COMPLETED
    result_value = True
     
    try:
        zendesk = ZendeskManager(user_email, api_token, server_address)
        comment = zendesk.add_comment_to_ticket(ticket_id=ticket_id, comment_body=comment_body, author_name=author_name, internal_note=is_internal_note)

        if comment:
            output_message = u"Ticket with id {} was updated with comment: {}".format(ticket_id, comment_body)
        else:
            output_message = u"There was a problem adding comment to ticket with id: {}.".format(ticket_id)
            result_value = False

    except Exception as e:
        output_message = u'Error executing action {}. Reason: {}'.format(ADD_COMMENT_TO_TICKET, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info(u'----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        u'\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
