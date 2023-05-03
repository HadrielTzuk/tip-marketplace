from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from VirusTotalManager import VirusTotalManager, ORDER_BY_MAPPING
from constants import PROVIDER_NAME, INTEGRATION_NAME, SEARCH_GRAPHS_SCRIPT_NAME, MAX_COUNT_OF_GRAPHS
from exceptions import VirusTotalBadRequest


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SEARCH_GRAPHS_SCRIPT_NAME

    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool)
    # Parameters
    query = extract_action_param(siemplify, param_name="Query", is_mandatory=True, print_value=True)
    order_by = extract_action_param(siemplify, param_name="Sort Field", is_mandatory=False, print_value=True)
    max_returned_graphs = extract_action_param(siemplify, param_name="Max Graphs To Return", is_mandatory=False,
                                               input_type=int, default_value=MAX_COUNT_OF_GRAPHS)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)

        graphs_data = manager.get_graph_details(query=query, order_by=ORDER_BY_MAPPING[order_by],
                                                limit=max_returned_graphs)

        if graphs_data:
            output_message = "Successfully returned graphs for the provided query in {}".format(PROVIDER_NAME)
            siemplify.result.add_result_json([graph.to_json_shorten() for graph in graphs_data])
        else:
            output_message = "No graphs were found for the provided query."
            result_value = False

    except VirusTotalBadRequest as err:
        output_message = "Action wasn't able to successfully return graph for the provided query in {}. Reason: {}."\
            .format(PROVIDER_NAME, err)
        result_value = False
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    except Exception as err:
        output_message = "Error executing action “Search Graphs”. Reason: {}".format(err)
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
