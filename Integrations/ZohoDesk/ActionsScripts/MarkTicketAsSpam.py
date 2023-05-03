from TIPCommon import extract_configuration_param, extract_action_param
from ZohoDeskManager import ZohoDeskManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from constants import (
    INTEGRATION_NAME,
    INTEGRATION_DISPLAY_NAME,
    MARK_TICKET_AS_SPAM_SCRIPT_NAME
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = MARK_TICKET_AS_SPAM_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client Secret",
                                                is_mandatory=True, remove_whitespaces=False)
    refresh_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Refresh Token",
                                                is_mandatory=False, remove_whitespaces=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    # Action configuration
    ticket_id = extract_action_param(siemplify, param_name="Ticket ID", is_mandatory=True, print_value=True)
    mark_contact = extract_action_param(siemplify, param_name="Mark Contact", print_value=True, input_type=bool)
    # mark_other_contact_tickets = extract_action_param(siemplify, param_name="Mark Other Contact Tickets",
    #                                                   print_value=True, input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = ZohoDeskManager(api_root=api_root, client_id=client_id, client_secret=client_secret,
                                  refresh_token=refresh_token, verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)
        manager.get_ticket(
            ticket_id=ticket_id,
            additional_fields=None
        )
        manager.mark_ticket_as_spam(ticket_id=ticket_id, mark_contact=mark_contact,
                                    mark_other_contact_tickets=False)
        output_message = f"Successfully marked a ticket as spam in {INTEGRATION_DISPLAY_NAME}"
    except Exception as error:
        output_message = f'Error executing action {MARK_TICKET_AS_SPAM_SCRIPT_NAME}. Reason: {error}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
