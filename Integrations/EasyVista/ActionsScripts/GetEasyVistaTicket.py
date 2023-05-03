from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction, ScriptResult
from EasyVistaManager import EasyVistaManager
from TIPCommon import extract_configuration_param, extract_action_param,flat_dict_to_csv
from EasyVistaExceptions import EasyVistaInternalError
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    GET_EASYVISTA_TICKET_ACTION
)
import datetime

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_EASYVISTA_TICKET_ACTION
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

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""

    try:
        easyvista_manager = EasyVistaManager(api_root=api_root,account_id=account_id, username=username,
                                 password=password, verify_ssl=verify_ssl)
        general_ticket_info = easyvista_manager.get_ticket_information(account_id, ticket_identifier)
        output_message += "Successfully returned EasyVista information for the ticket {0}.".format(ticket_identifier)

        siemplify.result.add_result_json(general_ticket_info.to_json())
        
        siemplify.result.add_data_table(
            title="EasyVista ticket {} information:".format(ticket_identifier),
            data_table=flat_dict_to_csv(general_ticket_info.to_table())
        )
 
    except EasyVistaInternalError as e:
        output_message = "Failed to get EasyVista information for the ticket {}. Reason: {}".format(ticket_identifier, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False       
     
    except Exception as e:
        output_message = 'Error executing action {}. Reason: {}'.format(GET_EASYVISTA_TICKET_ACTION, e)
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
