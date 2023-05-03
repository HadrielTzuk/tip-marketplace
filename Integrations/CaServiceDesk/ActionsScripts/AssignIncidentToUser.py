from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CaSoapManager import CaSoapManager

# Consts
ACTION_SCRIPT_NAME = 'Assign Incident To User'


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
    username = siemplify.parameters.get('Username')

    result_value = ca_manager.assign_incident_to_user(ticket_id, username)

    if result_value:
        output_message = 'Ticket with id "{0}" assigned to "{1}"'.format(ticket_id, unicode(username).encode('utf-8'))
    else:
        output_message = 'Ticket with id "{0}" was not assigned to "{1}"'.format(ticket_id, unicode(username).encode('utf-8'))

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
