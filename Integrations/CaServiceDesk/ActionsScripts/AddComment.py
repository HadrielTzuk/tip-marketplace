from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CaSoapManager import CaSoapManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('CaServiceDesk')
    api_root = conf['Api Root']
    username = conf['Username']
    password = conf['Password']
    
    ca_manager = CaSoapManager(api_root, username, password)

    ticket_id = siemplify.parameters['Ticket ID']
    comment = siemplify.parameters['Comment']

    add_comment_status = ca_manager.add_comment_to_incident(ticket_id, comment)

    if add_comment_status:
        output_message = 'Added comment to Incident {0}.'.format(ticket_id)
        result_value = 'true'

    else:
        output_message = 'There was a problem adding comment to ticket number {0}.'.format(ticket_id)
        result_value = 'false'

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
