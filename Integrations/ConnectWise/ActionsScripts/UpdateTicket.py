from SiemplifyUtils import output_handler
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
    summary = siemplify.parameters.get('Summary')
    ticket_type = siemplify.parameters.get('Type Name')
    subtype = siemplify.parameters.get('SubType Name')
    owner_name = siemplify.parameters.get('Owner Name')
    board = siemplify.parameters.get('Board')
    priority = siemplify.parameters.get('Priority')
    item = siemplify.parameters.get('Item Name')
    status = siemplify.parameters.get('Status')
    email_cc = siemplify.parameters.get('Email Note CC', '')
    email_cc = [single_value.strip() for single_value in email_cc.split(',') if single_value.strip()]

    ticket_params_list = [summary, ticket_type, subtype, owner_name, board, priority, item]
    # Execute Update Ticket.
    if not any(ticket_params_list) and status:
        result = connectwise_manager.update_ticket_status(ticket_id, status)
    else:
        # The result will be a ticket id.
        result = connectwise_manager.update_ticket(ticket_id, summary, ticket_type, subtype, item,
                                                   owner_name, board, priority, status, email_cc)

    if result:
        output_message = "Ticket with id {0} was updated successfully".format(ticket_id)
        result_value = result
    else:
        output_message = 'There was a updating ticket with id: {0}.'.format(ticket_id)
        result_value = False

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
