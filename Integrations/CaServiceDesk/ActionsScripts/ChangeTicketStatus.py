from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CaSoapManager import CaSoapManager

# Consts
ACTION_SCRIPT_NAME = 'Change Ticket Status'


@output_handler
def main():

    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_SCRIPT_NAME

    conf = siemplify.get_configuration('CaServiceDesk')

    api_root = conf['Api Root']
    username = conf['Username']
    password = conf['Password']

    ca_manager = CaSoapManager(api_root, username, password)

    # Parameters
    ticket_id = siemplify.parameters.get('Ticket ID')
    status = siemplify.parameters.get('Status').encode('utf-8')

    result_value = ca_manager.change_ticket_status(ticket_id, status)
    output_message = 'Ticket with id "{0}" status changed to "{1}"'.format(ticket_id, status)

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
