from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ZendeskManager import ZendeskManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
import re

INTEGRATION_NAME = u"Zendesk"
CREATE_TICKET = u"Create Ticket"
VALID_EMAIL_REGEXP = '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_TICKET
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")
    
    user_email = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name=u"User Email Address", is_mandatory=True, print_value=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name=u"Api Token", print_value=False, is_mandatory=True)
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name=u"Server Address", is_mandatory=True, print_value=True)
    
    subject = extract_action_param(siemplify, param_name=u"Subject", is_mandatory=True, print_value=True, input_type=unicode)
    description = extract_action_param(siemplify, param_name=u"Description", is_mandatory=True, print_value=True, input_type=unicode)
    assigned_user = extract_action_param(siemplify, param_name=u"Assigned User", is_mandatory=False, print_value=True, input_type=unicode)
    assignment_group = extract_action_param(siemplify, param_name=u"Assignment Group", is_mandatory=False, print_value=True, input_type=unicode)  
    priority = extract_action_param(siemplify, param_name=u"Priority", is_mandatory=False, print_value=True, input_type=unicode)
    ticket_type = extract_action_param(siemplify, param_name=u"Ticket Type", is_mandatory=False, print_value=True, input_type=unicode)        
    ticket_tag = extract_action_param(siemplify, param_name=u"Tag", is_mandatory=False, print_value=True, input_type=unicode)     
    internal_note = extract_action_param(siemplify, param_name=u"Internal Note", is_mandatory=False, print_value=True, input_type=bool)
    email_ccs = extract_action_param(siemplify, param_name=u"Email CCs", is_mandatory=False, print_value=True,
                                     input_type=unicode)
    validate_email_ccs = extract_action_param(siemplify, param_name=u"Validate Email CCs", is_mandatory=False,
                                              print_value=True, input_type=bool)
    tag = [ticket_tag]
    internal_note = not internal_note
    email_ccs = [item.strip() for item in email_ccs.rstrip(u',').split(u',')] if email_ccs else []
    
    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")    
    status = EXECUTION_STATE_COMPLETED
    result_value = True
     
    try:
        zendesk = ZendeskManager(user_email, api_token, server_address)
        invalid_emails = []
        for email in email_ccs:
            if not bool(re.search(VALID_EMAIL_REGEXP, email)):
                invalid_emails.append(email)

        if invalid_emails:
            raise Exception("the following emails are not valid: {}. Please check the spelling.".format(
                ', '.join(str(v) for v in invalid_emails)
            ))

        if validate_email_ccs:
            existing_emails = zendesk.get_users_email_addresses()
            for email in email_ccs:
                if email not in existing_emails:
                    raise Exception("users with the following emails were not found: {}. Please check the spelling "
                                    "or disable \"Validate Email CCs\" parameter.".format(email))

        new_ticket = zendesk.create_ticket(subject=subject, description=description, assigned_to=assigned_user,
                                           assignment_group=assignment_group, priority=priority,
                                           ticket_type=ticket_type, tags=tag, internal_note=internal_note,
                                           email_ccs=email_ccs)

        if new_ticket:
            ticket_id = new_ticket['ticket']['id']
            output_message = u"Successfully created ticket with id: {0}".format(str(ticket_id))
            result_value = ticket_id
        else:
            output_message = u'There was a problem creating ticket.'
            result_value = False
            
    except Exception as e:
        output_message = u'Error executing action {}. Reason: {}'.format(CREATE_TICKET, e)
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
