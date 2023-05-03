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

    # Get context alert properties.
    context_alert_id = siemplify.current_alert.external_id

    # Parameters.
    summary = context_alert_id
    company = siemplify.parameters['Company']
    owner_name = siemplify.parameters.get('Owner Name')
    board = siemplify.parameters['Board']
    status = siemplify.parameters['Status']
    priority_id = siemplify.parameters['Priority']
    initial_description = siemplify.parameters['Initial Description']

    # Execute Create Ticket.
    ticket_id = connectwise_manager.create_ticket(summary, company, board, status, priority_id, owner_name)

    if ticket_id:
        # Add initial description to ticket (as first comment)
        connectwise_manager.add_comment_to_ticket(ticket_id, initial_description)
        output_message = "Created ticket with id: {0}".format(ticket_id)
        result_value = ticket_id
        # Attach CW ticket id to alert.
        siemplify.update_alerts_additional_data({siemplify.current_alert.identifier: ticket_id})
    else:
        output_message = 'There was a problem creating ticket.'
        result_value = False

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
