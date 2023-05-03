import json
import sys
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from ServiceNowManager import ServiceNowManager, DEFAULT_TABLE
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, ADD_COMMENT_AND_WAIT_FOR_REPLY_SCRIPT_NAME
from dateutil import parser
from exceptions import ServiceNowNotFoundException, ServiceNowTableNotFoundException, ServiceNowRecordNotFoundException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_COMMENT_AND_WAIT_FOR_REPLY_SCRIPT_NAME
    siemplify.LOGGER.info('=' * 10 + ' Main - Param Init ' + '=' * 10)

    # Configuration.
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
    comment_to_add = extract_action_param(siemplify, param_name="Comment", print_value=True, is_mandatory=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    try:
        service_now_manager = ServiceNowManager(api_root=api_root, username=username, password=password,
                                                default_incident_table=default_incident_table, verify_ssl=verify_ssl,
                                                siemplify_logger=siemplify.LOGGER, client_id=client_id,
                                                client_secret=client_secret, refresh_token=refresh_token,
                                                use_oauth=use_oauth)

        service_now_manager.add_comment_to_incident(incident_number, comment_to_add)
        siemplify.LOGGER.info("Fetch {} comments".format(incident_number))

        last_comment_creation_time = ''
        comments_list = service_now_manager.get_incident_comments(incident_number)

        for comment in comments_list:
            if comment.value == comment_to_add:
                last_comment_creation_time = comment.sys_created_on

        param_json = {incident_number: str(last_comment_creation_time)}

        output_message = "Comment {} was posted at: {}".format(comment_to_add, last_comment_creation_time)
        result_value = json.dumps(param_json)
        status = EXECUTION_STATE_INPROGRESS
        siemplify.LOGGER.info(output_message)

    except ServiceNowNotFoundException as e:
        output_message = str(e) if isinstance(e, ServiceNowTableNotFoundException) else \
            'Incident with number \"{}\" was not found'.format(incident_number)
        result_value = False
        status = EXECUTION_STATE_COMPLETED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
    except Exception as e:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = "General error performing action {}. Reason: {}" \
            .format(ADD_COMMENT_AND_WAIT_FOR_REPLY_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.end(output_message, result_value, status)


def query_job():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_COMMENT_AND_WAIT_FOR_REPLY_SCRIPT_NAME
    # Configuration.
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

    try:
        service_now_manager = ServiceNowManager(api_root, username, password, default_incident_table, verify_ssl)

        # Extract last comment creation time and incident number
        additional_data = json.loads(siemplify.parameters["additional_data"])
        last_comment_creation_time = list(additional_data.values())[0]
        incident_number = list(additional_data.keys())[0]

        # A list of message objects with filtering
        siemplify.LOGGER.info("Search new comments in {} since {}".format(incident_number, last_comment_creation_time))
        comments_list = service_now_manager.get_incident_comments(incident_number)

        new_comment_list = []
        # Check if there is new comment
        for comment in comments_list:
            if parser.parse(comment.sys_created_on) > parser.parse(last_comment_creation_time):
                new_comment_list.append(comment.value)

        new_comment = ', '.join(new_comment_list)

        if new_comment:
            siemplify.LOGGER.info("New comment: {}".format(new_comment))
            output_message = "Successfully added comment \"{}\" to incident with number {}." \
                .format(new_comment, incident_number)
            status = EXECUTION_STATE_COMPLETED
            result_value = new_comment
        else:
            output_message = "Continuing...waiting for new comment to be added to {} incident".format(incident_number)
            siemplify.LOGGER.info("Not found new comment yet")
            status = EXECUTION_STATE_INPROGRESS
            result_value = siemplify.parameters["additional_data"]
    except Exception as e:
        output_message = "General error performing action {}. Reason: {}" \
            .format(ADD_COMMENT_AND_WAIT_FOR_REPLY_SCRIPT_NAME, e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info('\n  status: {}\n  result_value: {}\n  output_message: {}'
                          .format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main()
    else:
        query_job()
