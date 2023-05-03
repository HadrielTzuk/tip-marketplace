from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from ServiceNowManager import ServiceNowManager, DEFAULT_TABLE, ServiceNowRecordNotFoundException, \
    ServiceNowTableNotFoundException
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, GET_RECORD_DETAILS_SCRIPT_NAME
from exceptions import ServiceNowNotFoundException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_RECORD_DETAILS_SCRIPT_NAME

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
    # Parameters
    table_name = extract_action_param(siemplify, param_name="Table Name", is_mandatory=True, print_value=True)
    ticket_sys_id = extract_action_param(siemplify, param_name="Record Sys ID", is_mandatory=True, print_value=True)
    fields_str = extract_action_param(siemplify, param_name="Fields", is_mandatory=False, print_value=True)
    fields = [field.strip() for field in fields_str.split(',') if field.strip()] if fields_str else []

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = ServiceNowManager(api_root=api_root, username=username, password=password,
                                    default_incident_table=default_incident_table, verify_ssl=verify_ssl,
                                    siemplify_logger=siemplify.LOGGER, client_id=client_id,
                                    client_secret=client_secret, refresh_token=refresh_token,
                                    use_oauth=use_oauth)

        record = manager.get_record_details(ticket_sys_id=ticket_sys_id, fields=fields, table_name=table_name)
        # Add json result
        siemplify.result.add_result_json(record.to_json())
        output_message = "Successfully retrieved information about {} record with Sys ID {} in ServiceNow."\
            .format(table_name, ticket_sys_id)

    except ServiceNowNotFoundException as e:
        output_message = str(e) if isinstance(e, ServiceNowTableNotFoundException) else \
            "Action wasn't able to retrieve information about {} record with Sys ID {} in ServiceNow. Reason: {}"\
            .format(table_name, ticket_sys_id, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    except Exception as err:
        output_message = "Error executing action \"{}\". Reason: {}".format(GET_RECORD_DETAILS_SCRIPT_NAME, err)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info('\n  status: {}\n  result_value: {}\n  output_message: {}'
                          .format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
