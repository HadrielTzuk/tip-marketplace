from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ZendeskManager import ZendeskManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param

INTEGRATION_NAME = u"Zendesk"
UPDATE_TICKET = u"Update Ticket"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_TICKET
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")
    
    user_email = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name=u"User Email Address", is_mandatory=True, print_value=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name=u"Api Token", print_value=False, is_mandatory=True)
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name=u"Server Address", is_mandatory=True, print_value=True)
    
    
    ticket_id = extract_action_param(siemplify, param_name=u"Ticket ID", is_mandatory=True, print_value=True, input_type=unicode)
    subject = extract_action_param(siemplify, param_name=u"Subject", is_mandatory=False, print_value=True, input_type=unicode)
    assigned_user = extract_action_param(siemplify, param_name=u"Assigned User", is_mandatory=False, print_value=True, input_type=unicode)
    assignment_group = extract_action_param(siemplify, param_name=u"Assignment Group", is_mandatory=False, print_value=True, input_type=unicode)  
    priority = extract_action_param(siemplify, param_name=u"Priority", is_mandatory=False, print_value=True, input_type=unicode)
    ticket_type = extract_action_param(siemplify, param_name=u"Ticket Type", is_mandatory=False, print_value=True, input_type=unicode)        
    ticket_tag = extract_action_param(siemplify, param_name=u"Tag", is_mandatory=False, print_value=True, input_type=unicode) 
    ticket_status = extract_action_param(siemplify, param_name=u"Status", is_mandatory=False, print_value=True, input_type=unicode) 
    
    additional_comment = extract_action_param(siemplify, param_name=u"Additional Comment", is_mandatory=False, print_value=True, input_type=unicode)    
    internal_note = extract_action_param(siemplify, param_name=u"Internal Note", is_mandatory=False, print_value=True, input_type=bool)    
    internal_note = not internal_note
       
    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")    
    status = EXECUTION_STATE_COMPLETED
    result_value = True
     
    try:   
        zendesk = ZendeskManager(user_email, api_token, server_address)
        updated_ticket = zendesk.update_ticket(ticket_id=ticket_id, subject=subject, assigned_to=assigned_user,
                                    assignment_group=assignment_group, priority=priority, ticket_type=ticket_type,
                                           tag=ticket_tag, status=ticket_status)
        if additional_comment:
            _response = zendesk.add_comment_to_ticket(ticket_id=ticket_id, comment_body=additional_comment, internal_note=internal_note)
            
        if updated_ticket:
            output_message = u"Ticket with id {0} was updated successfully".format(ticket_id)

        else:
            output_message = u'There was a problem updating ticket with id: {0}.'.format(ticket_id)
            result_value = False

    except Exception as e:
        output_message = u'Error executing action {}. Reason: {}'.format(UPDATE_TICKET, e)
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
