import json
import sys
from SiemplifyUtils import output_handler
from TIPCommon import extract_action_param, extract_configuration_param, construct_csv
from SiemplifyAction import SiemplifyAction
from QRadarManager import QRadarManager
from ScriptResult import EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    RUN_AQL_QUERY_SCRIPT_NAME,
    AQL_QUERY_RESULT_TABLE_HEADER
)

@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = RUN_AQL_QUERY_SCRIPT_NAME
    mode = 'Main' if is_first_run else 'QueryState'

    siemplify.LOGGER.info('----------------- {} - Param Init -----------------'.format(mode))

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    api_version = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Version')

    siemplify.LOGGER.info('----------------- {} - Started -----------------'.format(mode))

    query = extract_action_param(siemplify, param_name='Query Format', is_mandatory=True, print_value=True)

    status = EXECUTION_STATE_INPROGRESS
    output_message = "Searching for query '{}'".format(query)

    try:
        manager = QRadarManager(api_root, api_token, api_version)
        # Create search id or get existing id from result_value
        result_value = manager.run_query(query) if is_first_run else siemplify.parameters['additional_data']

        if manager.is_search_completed(result_value):
            query_results = manager.get_completed_search_query_result(result_value)
            status = EXECUTION_STATE_COMPLETED
            query_results_values = list(filter(lambda value: value, query_results.values()))

            if not query_results_values:
                result_value = False
                output_message = 'No data found for query.'

            for query_value in query_results_values:
                siemplify.result.add_result_json(query_results)
                result_value = json.dumps(query_value)
                output_message = 'Found data for query.'
                siemplify.result.add_data_table(AQL_QUERY_RESULT_TABLE_HEADER, construct_csv(query_value))
                break

    except Exception as e:
        output_message = 'Failed to execute action, the error is {}'.format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- {} - Finished -----------------'.format(mode))
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == 'True'
    main(is_first_run)
