from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
# Imports
from SiemplifyAction import SiemplifyAction
from ConnectWiseManager import ConnectWiseManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    # Configuration.
    configuration_settings = siemplify.get_configuration('ConnectWise')
    company_url = configuration_settings['Api Root']
    company_name = configuration_settings['Company Name']
    public_key = configuration_settings['Public Key']
    private_key = configuration_settings['Private Key']
    client_id = configuration_settings['Client Id']
    connectwise_manager = ConnectWiseManager(company_url, company_name, public_key, private_key, client_id)

    # Parameters.
    ticket_id = siemplify.parameters['Ticket Id']
    # Change the ticket status.
    if siemplify.parameters.get('Custom Close Status'):
        custom_close_status = siemplify.parameters['Custom Close Status']
        ticket_id_result = connectwise_manager.close_ticket(ticket_id, custom_close_status)  # The result will be a ticket id.
    else:
        # Execute Close Ticket.
        ticket_id_result = connectwise_manager.close_ticket(ticket_id)  # The result will be a ticket id.

    if ticket_id_result:
        output_message = "Ticket with id {0} was closed.".format(ticket_id_result)
    else:
        output_message = 'There was a problem closing ticket with id: {0}.'.format(ticket_id)


    siemplify.end(output_message, ticket_id_result)


if __name__ == '__main__':
    main()
