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
    close_reason = siemplify.parameters['Close Reason']

    incident_id = ca_manager.close_incident(ticket_id, close_reason)

    if incident_id:
        output_message = 'Incident {0} closed successfully.'.format(ticket_id)
        result_value = 'true'

    else:
        output_message = 'There was a problem closing ticket number {0}.'.format(ticket_id)
        result_value = 'false'

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
