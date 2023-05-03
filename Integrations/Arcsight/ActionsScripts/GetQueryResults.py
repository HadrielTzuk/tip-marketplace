from SiemplifyUtils import output_handler
from ArcsightManager import ArcsightManager
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, dict_to_flat, construct_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, GET_QUERY_RESULTS_SCRIPT_NAME, DEFAULT_LIMIT


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_QUERY_RESULTS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    ca_certificate_file = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                      param_name="CA Certificate File")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)

    query_id = extract_action_param(siemplify, param_name="Query ID", print_value=True)
    limit = extract_action_param(siemplify, param_name="Max Items To Return", print_value=True,
                                 input_type=int, default_value=DEFAULT_LIMIT)
    query_name = extract_action_param(siemplify, param_name="Query Name", print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    map_columns = True
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    fetched_by_id = bool(query_id)

    try:
        if not query_name and not query_id:
            raise Exception("either ‘Query ID' or 'Query Name’ should be provided.")

        arcsight_manager = ArcsightManager(server_ip=api_root, username=username, password=password,
                                           verify_ssl=verify_ssl,
                                           ca_certificate_file=ca_certificate_file)
        arcsight_manager.login()

        if not query_id:
            query_id = arcsight_manager.get_query_uuid(query_name)

        result = arcsight_manager.get_query_result(query_id, limit)
        if result.rows_count:
            siemplify.result.add_data_table("Results", result.to_csv())
            siemplify.result.add_result_json(result.to_json(map_columns))
            output_message = "Successfully found results for query {} in {}"\
                .format('with ID {}'.format(query_id) if fetched_by_id else query_name, INTEGRATION_NAME)
        else:
            result_value = False
            output_message = "No results were found for query {} in {}"\
                .format('with ID {}'.format(query_id) if fetched_by_id else query_name, INTEGRATION_NAME)
        arcsight_manager.logout()

    except Exception as e:
        output_message = "Error executing action {}. Reason: {}".format(GET_QUERY_RESULTS_SCRIPT_NAME, e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
