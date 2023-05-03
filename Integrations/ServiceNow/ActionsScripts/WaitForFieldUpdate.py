from SiemplifyUtils import output_handler
import sys
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from ServiceNowManager import ServiceNowManager, DEFAULT_TABLE, ServiceNowRecordNotFoundException
from exceptions import ServiceNowRecordNotFoundException, ServiceNowNotFoundException, ServiceNowTableNotFoundException
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, WAIT_FOR_FIELD_UPDATE_SCRIPT_NAME

@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = WAIT_FOR_FIELD_UPDATE_SCRIPT_NAME
    mode = "Main" if is_first_run else "QueryState"

    siemplify.LOGGER.info("----------------- {} - Param Init -----------------".format(mode))

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           print_value=False)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           print_value=False)
    default_incident_table = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                         param_name="Incident Table", print_value=True,
                                                         default_value=DEFAULT_TABLE)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            print_value=False)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name="Client Secret", print_value=False)
    refresh_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name="Refresh Token", print_value=False)
    use_oauth = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                            param_name="Use Oauth Authentication", default_value=False,
                                            input_type=bool)

    table_name = extract_action_param(siemplify, param_name="Table Name", print_value=True)
    sys_id = extract_action_param(siemplify, param_name="Record Sys ID", print_value=True, is_mandatory=True)
    column_name = extract_action_param(siemplify, param_name="Field - Column name", print_value=True, is_mandatory=True)
    column_value = extract_action_param(siemplify, param_name="Field - Values", print_value=True, is_mandatory=True)
    values_list = [column_value.strip() for column_value in column_value.lower().split(',')] if column_value else []

    siemplify.LOGGER.info("----------------- {} - Started -----------------".format(mode))

    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        service_now_manager = ServiceNowManager(api_root=api_root, username=username, password=password,
                                                default_incident_table=default_incident_table, verify_ssl=verify_ssl,
                                                siemplify_logger=siemplify.LOGGER, client_id=client_id,
                                                client_secret=client_secret, refresh_token=refresh_token,
                                                use_oauth=use_oauth)

        ticket = service_now_manager.get_ticket_by_id(sys_id, table_name=table_name)

        if ticket.is_empty():
            raise ServiceNowRecordNotFoundException

        ticket_updated_field = ticket.get_value(column_name)

        if ticket.is_open:
            # Check if updated
            if ticket_updated_field in values_list:
                siemplify.LOGGER.info("Record with sys_id {} Field: {} was updated successfully to {}"
                                      .format(sys_id, column_name, ticket_updated_field))
                output_message = "Field \"{}\" of the record with Sys ID \"{}\" in table \"{}\" was updated to \"{}\"" \
                    .format(column_name, sys_id, table_name, ticket_updated_field)
            else:
                output_message = "Continuing...waiting for record with sys_id {} to be updated".format(sys_id)
                status = EXECUTION_STATE_INPROGRESS
                siemplify.LOGGER.info("Record with sys_id {} still not changed. Current Field value: {}"
                                      .format(sys_id, ticket_updated_field))
        else:
            output_message = "Record with sys_id {} was {}".format(sys_id, ticket.state)
            siemplify.LOGGER.info(output_message)

        if status == EXECUTION_STATE_COMPLETED:
            siemplify.result.add_result_json(ticket.to_json())

    except ServiceNowNotFoundException as e:
        output_message = str(e) if isinstance(e, ServiceNowTableNotFoundException) else \
            'Record with Sys ID \'{}\' was not found in table \'{}\''.format(sys_id, table_name)
        result_value = False
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    except Exception as e:
        output_message = 'Error executing action \"{}\". Reason: {}'.format(WAIT_FOR_FIELD_UPDATE_SCRIPT_NAME, e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)
