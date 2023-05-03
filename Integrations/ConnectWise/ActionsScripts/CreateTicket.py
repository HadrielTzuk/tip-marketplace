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
    result_value = False

    # Parameters.
    company = siemplify.parameters['Company']
    owner_name = siemplify.parameters.get('Owner Name')
    board = siemplify.parameters['Board']
    summary = siemplify.parameters['Summary']
    status = siemplify.parameters['Status']
    priority_id = siemplify.parameters['Priority']
    email_cc = siemplify.parameters.get('Email Note CC', '')
    email_cc = [single_value.strip() for single_value in email_cc.split(',') if single_value.strip()]

    # Execute Create Ticket.
    ticket_id = connectwise_manager.create_ticket(summary, company, board, status, priority_id, owner_name, email_cc)

    if ticket_id:
        output_message = "Created ticket with id: {0}".format(ticket_id)
        result_value = ticket_id
    else:
        output_message = 'There was a problem creating ticket.'

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()