from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from ServiceNowManager import ServiceNowManager, DEFAULT_TABLE
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, ADD_COMMENT_SCRIPT_NAME
from exceptions import ServiceNowNotFoundException, ServiceNowTableNotFoundException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_COMMENT_SCRIPT_NAME
    siemplify.LOGGER.info('=' * 10 + ' Main - Param Init ' + '=' * 10)

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
    incident_number = extract_action_param(siemplify, param_name="Incident Number", print_value=True,
                                           is_mandatory=True)
    comment = extract_action_param(siemplify, param_name="Comment", print_value=True, is_mandatory=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        service_now_manager = ServiceNowManager(api_root=api_root, username=username, password=password,
                                                default_incident_table=default_incident_table, verify_ssl=verify_ssl,
                                                siemplify_logger=siemplify.LOGGER, client_id=client_id,
                                                client_secret=client_secret, refresh_token=refresh_token,
                                                use_oauth=use_oauth)
        service_now_manager.add_comment_to_incident(incident_number, comment)

        output_message = "Successfully added comment \"{}\" to incident with number {}."\
            .format(comment, incident_number)
    except ServiceNowNotFoundException as e:
        output_message = str(e) if isinstance(e, ServiceNowTableNotFoundException) else \
            'Incident with number \"{}\" was not found'.format(incident_number)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
    except Exception as e:
        output_message = "General error performing action {}. Reason: {}".format(ADD_COMMENT_SCRIPT_NAME, e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info('\n  status: {}\n  result_value: {}\n  output_message: {}'
                          .format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
