from ServiceNowManager import ServiceNowManager, DEFAULT_TABLE
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param, dict_to_flat, flat_dict_to_csv
from constants import INTEGRATION_NAME, GET_INCIDENT_SCRIPT_NAME
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from exceptions import ServiceNowNotFoundException, ServiceNowTableNotFoundException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_INCIDENT_SCRIPT_NAME

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
    incident_number = extract_action_param(siemplify, param_name="Incident Number", print_value=True,
                                           is_mandatory=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        service_now_manager = ServiceNowManager(api_root=api_root, username=username, password=password,
                                                default_incident_table=default_incident_table, verify_ssl=verify_ssl,
                                                siemplify_logger=siemplify.LOGGER, client_id=client_id,
                                                client_secret=client_secret, refresh_token=refresh_token,
                                                use_oauth=use_oauth)
        incident = service_now_manager.get_ticket(incident_number)
        # Add csv table
        siemplify.result.add_entity_table('Incident details:', incident.to_csv())
        output_message = "Successfully retrieved incident with number \"{}\".".format(incident_number)
        siemplify.result.add_result_json(incident.to_json())

    except ServiceNowNotFoundException as e:
        output_message = str(e) if isinstance(e, ServiceNowTableNotFoundException) else \
            'Incident with number \"{}\" was not found'.format(incident_number)
        result_value = False
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
    except Exception as e:
        output_message = "General error performing action {}. Reason: {}".format(GET_INCIDENT_SCRIPT_NAME, e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info('\n  status: {}\n  result_value: {}\n  output_message: {}'
                          .format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
