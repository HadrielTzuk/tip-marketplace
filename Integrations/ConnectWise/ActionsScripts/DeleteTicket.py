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

    # Execute Delete Ticket.
    result = connectwise_manager.delete_ticket(ticket_id)

    if result:
        output_message = "Ticket with id {0} was deleted.".format(ticket_id)
        result_value = ticket_id
    else:
        output_message = 'There was a problem delete ticket with id: {0}.'.format(ticket_id)
        result_value = False

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
