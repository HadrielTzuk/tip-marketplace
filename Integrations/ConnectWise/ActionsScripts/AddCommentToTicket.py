from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
# Imports
from SiemplifyAction import SiemplifyAction
from ConnectWiseManager import ConnectWiseManager


@output_handler
def main():

    # Variables Definitions.
    output_message = ''
    result_value = False

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
    comment = siemplify.parameters['Comment']
    is_internal = siemplify.parameters.get('Internal', '').lower == 'true'
    
    # Execute Update Ticket.
    result = connectwise_manager.add_comment_to_ticket(ticket_id, comment, is_internal)  # The result will be a ticket id.

    if result:
        output_message = "Ticket with id {0} was updated with comment: {1}".format(ticket_id, comment)
        result_value = result
    else:
        output_message = 'There was a problem adding comment to ticket with id: {0}.'.format(ticket_id)
        result_value = False

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
