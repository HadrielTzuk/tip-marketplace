from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CaSoapManager import CaSoapManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS
import sys


# Consts
ACTION_SCRIPT_NAME = 'CA Service Desk_Wait_For_Status_Change'


@output_handler
def main():

    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_SCRIPT_NAME
    conf = siemplify.get_configuration('CaServiceDesk')

    api_root = conf['Api Root']
    username = conf['Username']
    password = conf['Password']
    ticket_fields_str = conf.get('Ticket Fields', '')

    ticket_fields = ticket_fields_str.split(',')

    ca_manager = CaSoapManager(api_root, username, password)
    ticket_id = siemplify.parameters.get('Ticket ID')
    expected_ticket_status = siemplify.parameters.get('Expected Ticket Status Name')

    siemplify.LOGGER.info(u"Fetching current status of ticket {}".format(ticket_id))

    try:
        current_ticket_status = ca_manager.get_ticket_status(ticket_id)

        if isinstance(current_ticket_status, str):
            current_ticket_status = current_ticket_status.decode("utf8")

    except Exception as e:
        siemplify.LOGGER.error(u"Unable to get ticket {} status.".format(ticket_id))
        siemplify.LOGGER.exception(e)
        raise

    if current_ticket_status == expected_ticket_status:
        siemplify.LOGGER.info(u"Ticket {} reached status: {}".format(ticket_id, expected_ticket_status))
        output_message = u"Ticket status is already: {0}.".format(current_ticket_status)
        ticket_data = ca_manager.get_incident_by_id(ticket_id, ticket_fields)
        siemplify.result.add_result_json(ticket_data)
        siemplify.end(output_message, 'true')

    else:
        siemplify.LOGGER.info(u"Ticket {} current status: {}. Waiting.".format(ticket_id, current_ticket_status))
        output_message = u"Current ticket status is: {0}, keeping tracking ticket.".format(current_ticket_status)
        siemplify.end(output_message, 'false', EXECUTION_STATE_INPROGRESS)


def query_job():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_SCRIPT_NAME

    siemplify.LOGGER.info(u"Starting async action.")

    conf = siemplify.get_configuration('CaServiceDesk')
    api_root = conf['Api Root']
    username = conf['Username']
    password = conf['Password']
    ticket_fields_str = conf.get('Ticket Fields', '')

    ticket_fields = ticket_fields_str.split(',')

    siemplify.LOGGER.info(u"Connecting to CA")
    ca_manager = CaSoapManager(api_root, username, password)
    ticket_id = siemplify.parameters.get('Ticket ID')

    expected_ticket_status = siemplify.parameters.get('Expected Ticket Status Name')

    try:
        current_ticket_status = ca_manager.get_ticket_status(ticket_id)

        if isinstance(current_ticket_status, str):
            current_ticket_status = current_ticket_status.decode("utf8")

    except Exception as e:
        siemplify.LOGGER.error(u"Unable to get ticket {} status.".format(ticket_id))
        siemplify.LOGGER.exception(e)
        raise

    if current_ticket_status == expected_ticket_status:
        siemplify.LOGGER.info(u"Ticket {} reached status: {}".format(ticket_id, expected_ticket_status))
        output_massage = u"Ticket status was changed to expected status: {0}.".format(expected_ticket_status)
        ticket_data = ca_manager.get_incident_by_id(ticket_id, ticket_fields)
        siemplify.result.add_result_json(ticket_data)
        siemplify.end(output_massage, "true", EXECUTION_STATE_COMPLETED)

    else:
        siemplify.LOGGER.info(u'Current ticket status is: {0}, keeping'
                              u' tracking ticket with ID: {1}, waiting for status: {2}'.format(current_ticket_status,
                                                                                              ticket_id,
                                                                                              expected_ticket_status))

        output_massage = u"Current ticket status is: {0}, keeping tracking ticket.".format(current_ticket_status)
        siemplify.end(output_massage, "false", EXECUTION_STATE_INPROGRESS)


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main()
    else:
        query_job()

