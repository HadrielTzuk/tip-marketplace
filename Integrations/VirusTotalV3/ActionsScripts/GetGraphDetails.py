from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from VirusTotalManager import VirusTotalManager
from constants import PROVIDER_NAME, INTEGRATION_NAME, GET_GRAPH_DETAILS_SCRIPT_NAME, DEFAULT_COMMENTS_COUNT, \
    GRAPHS_TABLE_TITLE
from exceptions import ForceRaiseException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_GRAPH_DETAILS_SCRIPT_NAME

    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool)
    # Parameters
    graphs = extract_action_param(siemplify, param_name="Graph ID", is_mandatory=True, print_value=True)
    max_returned_links = extract_action_param(siemplify, param_name="Max Links To Return", is_mandatory=False,
                                              input_type=int, default_value=DEFAULT_COMMENTS_COUNT)
    graph_ids = [graph_id.strip() for graph_id in graphs.split(',') if graph_id.strip()] if graphs else []

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    successful_graphs = []
    failed_graphs = []
    results = []

    try:
        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)

        for graph_id in graph_ids:
            try:
                graph_result = manager.get_graph(graph_id=graph_id, limit=max_returned_links)

                if graph_result:
                    # Create Case wall table for each graph_id
                    siemplify.result.add_data_table(title=GRAPHS_TABLE_TITLE.format(graph_id),
                                                    data_table=construct_csv(graph_result.to_table()))
                    results.append(graph_result)

                    successful_graphs.append(graph_id)

            except Exception as err:
                if isinstance(err, ForceRaiseException):
                    raise
                failed_graphs.append(graph_id)
                siemplify.LOGGER.error("Action wasn't able to retrieve data for {}: Reason: {}".format(graph_id, err))
                siemplify.LOGGER.exception(err)

        if results:
            siemplify.result.add_result_json([graph.to_json() for graph in results])

        if successful_graphs:
            output_message += "Successfully returned details about the following graphs in {}: \n {} \n"\
                .format(PROVIDER_NAME, ', '.join(successful_graphs))

        if failed_graphs:
            output_message += "Action wasn’t able to return details about the following graphs in {}: \n {} \n" \
                .format(PROVIDER_NAME, ', '.join(failed_graphs))

        if not successful_graphs:
            output_message = "No information about the provided graphs was found."
            result_value = False

    except Exception as err:
        output_message = "Error executing action “Get Graph Details”. Reason: {}".format(err)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()

