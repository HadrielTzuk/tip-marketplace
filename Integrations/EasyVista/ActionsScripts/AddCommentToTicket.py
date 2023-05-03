from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction, ScriptResult
from EasyVistaManager import EasyVistaManager
from TIPCommon import extract_configuration_param, extract_action_param
from EasyVistaExceptions import EasyVistaInternalError
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    ADD_COMMENT_TO_TICKET
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_COMMENT_TO_TICKET
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Root")
    account_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Account ID")
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Username")
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    # Action Parameters
    ticket_identifier = extract_action_param(siemplify, param_name="Ticket Identifier", is_mandatory=True, input_type=str)
    comment = extract_action_param(siemplify, param_name="Comment", is_mandatory=True, input_type=str)
    
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        easyvista_manager = EasyVistaManager(api_root=api_root,account_id=account_id, username=username,
                                 password=password, verify_ssl=verify_ssl)
        easyvista_manager.add_comment(account_id, ticket_identifier, comment)
        output_message = "Successfully added a comment to the EasyVista ticket {0}.".format(ticket_identifier)

    except EasyVistaInternalError as e:
        output_message = "Failed to add a comment to the EasyVista ticket {}. Reason: {}".format(ticket_identifier, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False        

    except Exception as e:
        output_message = 'Error executing action {}. Reason: {}'.format(ADD_COMMENT_TO_TICKET, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
