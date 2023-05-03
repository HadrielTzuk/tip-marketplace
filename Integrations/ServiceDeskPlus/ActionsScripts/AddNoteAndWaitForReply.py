from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS
from ServiceDeskPlusManager import ServiceDeskPlusManager
import sys


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = 'ServiceDesk Plus - Add Note And Wait For Reply'
    siemplify.LOGGER.info("=======Action START=======")

    conf = siemplify.get_configuration('ServiceDeskPlus')
    api_root = conf['Api Root']
    api_key = conf['Api Key']

    service_desk_plus_manager = ServiceDeskPlusManager(api_root, api_key)

    # Parameters
    request_id = siemplify.parameters['Request ID']
    note_text = siemplify.parameters['Note']
    is_public = siemplify.parameters.get('Is Public', 'false').lower() == 'true'

    service_desk_plus_manager.add_note(request_id, is_public, note_text)

    last_note_creation_time = ''
    notes_list = service_desk_plus_manager.get_request_notes(request_id)

    for note in sorted(notes_list, key=lambda x: x['notesdate'], reverse=True):
        if note['notestext'] == note_text:
            last_note_creation_time = str(note['notesdate'])

    siemplify.LOGGER.info("Note {0} was posted at: {1}".format(note_text, last_note_creation_time))

    output_message = "Note {0} was posted at: {1}".format(note_text, last_note_creation_time)
    siemplify.end(output_message, str(last_note_creation_time), EXECUTION_STATE_INPROGRESS)


def query_job():
    siemplify = SiemplifyAction()
    siemplify.script_name = 'ServiceDesk Plus - Add Note And Wait For Reply'
    siemplify.LOGGER.info("=======Action START=======")

    conf = siemplify.get_configuration('ServiceDeskPlus')
    api_root = conf['Api Root']
    api_key = conf['Api Key']

    service_desk_plus_manager = ServiceDeskPlusManager(api_root, api_key)

    # Parameters
    request_id = siemplify.parameters['Request ID']

    # Extract last note creation time and incident number
    last_note_creation_time = siemplify.parameters["additional_data"]

    # A list of message objects with filtering
    siemplify.LOGGER.info("Search new notes in {0} since {1}".format(request_id, last_note_creation_time))

    notes_list = service_desk_plus_manager.get_request_notes(request_id)
    new_notes = []

    # Check if there is new note
    for note in notes_list:
        if long(note['notesdate']) > long(last_note_creation_time):
            new_notes.append(unicode(note['notestext']).encode("utf8"))

    if new_notes:
        siemplify.LOGGER.info("New notes: {0}".format(", ".join(new_notes)))
        siemplify.LOGGER.info("=======Action DONE=======")
        output_message = "Request {0} has new notes: {1}".format(request_id, ", ".join(new_notes))
        siemplify.end(output_message, ", ".join(new_notes), EXECUTION_STATE_COMPLETED)
    else:
        output_message = "Continuing...waiting for new notes to be added to request {0}".format(request_id)
        siemplify.LOGGER.info("Not found new notes yet")
        siemplify.end(output_message, siemplify.parameters["additional_data"], EXECUTION_STATE_INPROGRESS)


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main()
    else:
        query_job()
