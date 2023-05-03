from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from ServiceNowManager import ServiceNowManager, DEFAULT_TABLE
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import INTEGRATION_NAME, GET_USER_DETAILS_SCRIPT_NAME, USERS_CVS_FILE_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_USER_DETAILS_SCRIPT_NAME

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
    user_sys_ids_str = extract_action_param(siemplify, param_name="User Sys IDs", print_value=True, is_mandatory=True)
    user_sys_ids = [sys_id.strip() for sys_id in user_sys_ids_str.split(',') if sys_id] if user_sys_ids_str else []

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    success_ids, failed_ids = [], []

    try:
        manager = ServiceNowManager(api_root=api_root, username=username, password=password,
                                    default_incident_table=default_incident_table, verify_ssl=verify_ssl,
                                    siemplify_logger=siemplify.LOGGER, client_id=client_id,
                                    client_secret=client_secret, refresh_token=refresh_token,
                                    use_oauth=use_oauth)

        if user_sys_ids:
            users = manager.get_user_details_by_sys_ids(sys_ids=user_sys_ids)
            success_ids = [user.sys_id for user in users]
            failed_ids = [item for item in user_sys_ids if item not in success_ids]

            if users:
                # Add json result
                siemplify.result.add_result_json([user.to_json() for user in users])
                # Add data to csv file
                siemplify.result.add_data_table(title=USERS_CVS_FILE_NAME, data_table=construct_csv(
                    [user.to_table() for user in users]))

        if success_ids:
            output_message = "Successfully retrieved information about users from ServiceNow with the " \
                              "following Sys IDs:\n {} \n".format(', '.join(success_ids))

        if failed_ids:
            output_message += "Action wasn't able to retrieve information about the users in Service Now with the " \
                              "following Sys IDs:\n {} \n".format(', '.join(failed_ids))

        if not success_ids:
            output_message = "Information about the users with specified Sys IDs was not found in Service Now"
            result_value = False

    except Exception as err:
        output_message = "Error executing action '{}'. Reason: {}".format(GET_USER_DETAILS_SCRIPT_NAME, err)
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
