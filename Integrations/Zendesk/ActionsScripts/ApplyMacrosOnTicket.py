from SiemplifyUtils import output_handler
# Imports
from SiemplifyAction import SiemplifyAction
from ZendeskManager import ZendeskManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration("Zendesk")
    user_email = conf['User Email Address']
    api_token = conf['Api Token']
    server_address = conf['Server Address']
    zendesk = ZendeskManager(user_email, api_token, server_address)

    ticket_id = siemplify.parameters['Ticket ID']
    macro_name = siemplify.parameters['Macro Title']
    ticket_data = zendesk.apply_macro_on_ticket(ticket_id, macro_name)

    if ticket_data:
        output_message = "Successfully apply macro {0} on ticket #{1}".format(macro_name, str(ticket_id))
        result_value = 'true'
    else:
        output_message = 'There was a problem applying macro {0} om ticket #{1}.'.format(macro_name, str(ticket_id))
        result_value = 'false'

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
