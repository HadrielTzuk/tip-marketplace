import sys
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from ServiceNowManager import ServiceNowManager, DEFAULT_TABLE
from exceptions import ServiceNowIncidentNotFoundException, ServiceNowNotFoundException
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, WAIT_FOR_STATUS_UPDATE_SCRIPT_NAME


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = WAIT_FOR_STATUS_UPDATE_SCRIPT_NAME
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
    # Parameters
    incident_number = extract_action_param(siemplify, param_name="Incident Number", print_value=True,
                                           is_mandatory=True)
    statuses = extract_action_param(siemplify, param_name="Statuses", print_value=True, is_mandatory=True)
    statuses_list = [status.strip() for status in statuses.lower().split(',')] if statuses else []

    siemplify.LOGGER.info("----------------- {} - Started -----------------".format(mode))

    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        service_now_manager = ServiceNowManager(api_root=api_root, username=username, password=password,
                                                default_incident_table=default_incident_table, verify_ssl=verify_ssl,
                                                siemplify_logger=siemplify.LOGGER, client_id=client_id,
                                                client_secret=client_secret, refresh_token=refresh_token,
                                                use_oauth=use_oauth)
        # # Get ticket status
        ticket = service_now_manager.get_ticket(incident_number)

        if ticket.state.lower() in statuses_list:
            # Incident state was updated
            siemplify.LOGGER.info("Incident {} Status: {}".format(incident_number, ticket.state))
            output_message = "Status of the incident with number {} was updated to \"{}\"" \
                .format(incident_number, ticket.state)
            siemplify.result.add_result_json(ticket.to_json())
        else:
            output_message = "Continuing...waiting for incident {} status to be updated".format(incident_number)
            status = EXECUTION_STATE_INPROGRESS
            siemplify.LOGGER.info(
                "Incident {} status still not changed. Current status: {}".format(incident_number, ticket.state))

    except ServiceNowNotFoundException as e:
        output_message = 'Incident with number \'{}\' was not found'.format(incident_number)
        result_value = False
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
    except Exception as e:
        output_message = 'Error executing action \"{}\". Reason: {}'.format(WAIT_FOR_STATUS_UPDATE_SCRIPT_NAME, e)
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
