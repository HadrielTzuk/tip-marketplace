from TIPCommon import extract_configuration_param, extract_action_param

from FreshworksFreshserviceManager import FreshworksFreshserviceManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import (
    INTEGRATION_IDENTIFIER,
    INTEGRATION_DISPLAY_NAME,
    ADD_TICKET_NOTE_SCRIPT_NAME,
    PRIVATE_NOTE
)
from exceptions import (
    FreshworksFreshserviceNotFoundError,
    FreshworksFreshserviceNegativeValueException
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_IDENTIFIER} - {ADD_TICKET_NOTE_SCRIPT_NAME}"
    siemplify.LOGGER.info("=================== Main - Param Init ===================")

    # Integration configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name="API Key",
                                          is_mandatory=True, print_value=False, remove_whitespaces=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name='Verify SSL', input_type=bool,
                                             is_mandatory=True, default_value=True, print_value=True)

    # Action configuration
    note_type = extract_action_param(siemplify, param_name="Note Type", print_value=True, default_value=PRIVATE_NOTE, is_mandatory=False)
    note_text = extract_action_param(siemplify, param_name="Note Text", print_value=True, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    # Action results
    status = EXECUTION_STATE_COMPLETED
    result_value = False

    try:
        ticket_id = extract_action_param(siemplify, param_name="Ticket ID", print_value=True, input_type=int, is_mandatory=True)
        if ticket_id < 0:
            raise FreshworksFreshserviceNegativeValueException("\"Ticket ID\" should be a positive number.")

        manager = FreshworksFreshserviceManager(
            api_root=api_root,
            api_key=api_key,
            verify_ssl=verify_ssl,
            siemplify=siemplify,
            force_test_connectivity=True
        )

        try:
            conversation = manager.add_ticket_note(
                ticket_id=ticket_id,
                note_text=note_text,
                is_private=True if note_type == PRIVATE_NOTE else False
            )
            siemplify.result.add_result_json({"conversation": conversation.to_json()})
            output_message = f"New {note_type.lower()} note is added to ticket {ticket_id}."
            result_value = True
        except FreshworksFreshserviceNotFoundError:
            output_message = f"Ticket {ticket_id} was not found in {INTEGRATION_DISPLAY_NAME}."

    except Exception as error:
        output_message = f"Error executing action \"{ADD_TICKET_NOTE_SCRIPT_NAME}\". Reason: {error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
