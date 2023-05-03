from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from ServiceNowManager import ServiceNowManager, DEFAULT_TABLE
from exceptions import ServiceNowNotFoundException, ServiceNowTableNotFoundException
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import INTEGRATION_NAME, LIST_CMDB_RECORDS_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_CMDB_RECORDS_SCRIPT_NAME

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

    # Action params
    class_name = extract_action_param(siemplify, param_name="Class Name", is_mandatory=True, print_value=True)
    query_filter = extract_action_param(siemplify, param_name="Query Filter", is_mandatory=False, print_value=True)
    max_records_to_return = extract_action_param(siemplify, param_name="Max Records To Return", is_mandatory=False,
                                                 print_value=True, input_type=int, default_value=50)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    result_value = True
    execution_status = EXECUTION_STATE_COMPLETED

    try:
        service_now_manager = ServiceNowManager(api_root=api_root, username=username, password=password,
                                                default_incident_table=default_incident_table, verify_ssl=verify_ssl,
                                                siemplify_logger=siemplify.LOGGER, client_id=client_id,
                                                client_secret=client_secret, refresh_token=refresh_token,
                                                use_oauth=use_oauth)
        result = service_now_manager.list_cmdb_records(class_name=class_name, query_filter=query_filter,
                                                       max_records_to_return=max_records_to_return)

        if result:
            siemplify.result.add_result_json({
                'result': [cmdb_record.to_json() for cmdb_record in result]
            })
            output_message = "Successfully listed CMDB records for the class: {} in Service Now.".format(class_name)
            siemplify.result.add_data_table(title="{} records".format(class_name), data_table=construct_csv(
                [cmdb_record.to_table() for cmdb_record in result]))
        else:
            output_message = "Action wasn’t able to list CMDB records for the Class {} in Service Now." \
                .format(class_name)

    except ServiceNowNotFoundException as e:
        output_message = str(e) if isinstance(e, ServiceNowTableNotFoundException) else \
            "Action wasn’t able to list CMDB records for the class: {class_name} in Service Now. " \
                         "Reason: class: {class_name} was not found in Service Now.".format(class_name=class_name)
        result_value = False
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    except Exception as e:
        output_message = "General error performing action \"List CMDB Records\". Reason: {}".format(e)
        result_value = False
        execution_status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info('\n  status: {}\n  result_value: {}\n  output_message: {}'
                          .format(execution_status, result_value, output_message))
    siemplify.end(output_message, result_value, execution_status)


if __name__ == '__main__':
    main()
