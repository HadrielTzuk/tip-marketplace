from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ServiceNowManager import ServiceNowManager, DEFAULT_TABLE
import json
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, CREATE_RECORD_SCRIPT_NAME
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from exceptions import ServiceNowNotFoundException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_RECORD_SCRIPT_NAME

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
    table_name = extract_action_param(siemplify, param_name="Table Name", print_value=True,
                                      default_value=default_incident_table)
    json_data = extract_action_param(siemplify, param_name="Object Json Data", print_value=True)

    try:
        json_data = json.loads(json_data)
    except:
        siemplify.LOGGER.info('Provided "Object Json Data" is not valid JSON. Using empty json instead')
        json_data = {}

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    result_value = False
    status = EXECUTION_STATE_COMPLETED

    try:
        service_now_manager = ServiceNowManager(api_root=api_root, username=username, password=password,
                                                default_incident_table=default_incident_table, verify_ssl=verify_ssl,
                                                siemplify_logger=siemplify.LOGGER, client_id=client_id,
                                                client_secret=client_secret, refresh_token=refresh_token,
                                                use_oauth=use_oauth)
        obj, not_used_custom_keys = service_now_manager.create_object(json_data, table_name=table_name)

        if obj.is_empty():
            output_message = "Failed to create ServiceNow record in {}.".format(table_name)
        else:
            result_value = obj.sys_id
            siemplify.result.add_result_json(obj.to_json())

            output_message = "Successfully created record with Sys ID {} in table \"{}\".".format(obj.sys_id,
                                                                                                  table_name)
            if not_used_custom_keys:
                output_message += "\nThe following fields were not processed, when creating a record: {}" \
                    .format(', '.join(not_used_custom_keys))

    except ServiceNowNotFoundException as e:
        output_message = str(e)
        result_value = False
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
    except Exception as e:
        output_message = "General error performing action {}. Reason: {}".format(CREATE_RECORD_SCRIPT_NAME, e)
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
