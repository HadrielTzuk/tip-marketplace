import datetime
import sys

from TIPCommon import extract_action_param, extract_configuration_param, construct_csv

from QRadarManager import QRadarManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_string_to_datetime
from UtilsManager import remove_none_params
from constants import (
    INTEGRATION_NAME,
    SIMPLE_AQL_SEARCH_SCRIPT_NAME,
    MAPPED_TIME_FRAMES,
    LAST_HOUR,
    ASCENDING,
    FLOWS,
    FLOWS_DATA_TYPE_IDENTIFIER,
    EVENTS_DATA_TYPE_IDENTIFIER,
    CUSTOM_TIME_FRAME,
    DATETIME_FORMAT
)


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = SIMPLE_AQL_SEARCH_SCRIPT_NAME
    mode = 'Main' if is_first_run else 'QueryState'

    siemplify.LOGGER.info('================= {} - Param Init ================='.format(mode))

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    api_version = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Version')

    siemplify.LOGGER.info('----------------- {} - Started -----------------'.format(mode))

    table_name = extract_action_param(siemplify, param_name='Table Name', is_mandatory=True, default_value=FLOWS, print_value=True)
    fields_to_return = extract_action_param(siemplify, param_name='Fields To Return', is_mandatory=False, default_value="*",
                                            print_value=True)
    where_filter = extract_action_param(siemplify, param_name='Where Filter', is_mandatory=False, print_value=True)
    time_frame = extract_action_param(siemplify, param_name='Time Frame', is_mandatory=False, default_value=LAST_HOUR, print_value=True)
    start_time = extract_action_param(siemplify, param_name='Start Time', is_mandatory=False, print_value=True)
    end_time = extract_action_param(siemplify, param_name='End Time', is_mandatory=False, print_value=True)
    sort_field = extract_action_param(siemplify, param_name='Sort Field', is_mandatory=False, print_value=True)
    sort_order = extract_action_param(siemplify, param_name='Sort Order', is_mandatory=False, default_value=ASCENDING, print_value=True)

    status = EXECUTION_STATE_INPROGRESS

    try:
        max_results_to_return = extract_action_param(siemplify, param_name='Max Results To Return', is_mandatory=False, default_value=50,
                                                     input_type=int, print_value=True)
        if isinstance(max_results_to_return, int) and max_results_to_return <= 0:
            raise Exception("\"Max Results To Return\" must be greater than 0.")

        if time_frame == CUSTOM_TIME_FRAME:
            time_delta = None
            if not start_time:
                raise Exception("Parameter \"Start Time\" must be provided if \"Custom\" is selected for time frame.")
            if not end_time:
                end_time = datetime.datetime.utcnow().strftime(DATETIME_FORMAT)
            else:
                end_time = convert_string_to_datetime(end_time).strftime(DATETIME_FORMAT)
            start_time = convert_string_to_datetime(start_time).strftime(DATETIME_FORMAT)
        else:
            time_delta = MAPPED_TIME_FRAMES[time_frame]
            if start_time:
                siemplify.LOGGER.info("Provided \"Start Time\" parameter will be ignored because \"Time Frame\" parameter selected "
                                      "is not \"Custom\"")
            if end_time:
                siemplify.LOGGER.info("Provided \"End Time\" parameter will be ignored because \"Time Frame\" parameter selected "
                                      "is not \"Custom\"")
            start_time = end_time = None
        sort_order = None if not sort_field else sort_order
        manager = QRadarManager(api_root, api_token, api_version)
        query = manager.build_aql_query(
            **remove_none_params(
                select_fields=fields_to_return,
                table_name=FLOWS_DATA_TYPE_IDENTIFIER if table_name == FLOWS else EVENTS_DATA_TYPE_IDENTIFIER,
                where_condition=where_filter,
                sort_by_field=sort_field,
                sort_order=sort_order,
                limit=max_results_to_return,
                time_delta=time_delta,
                start_time=start_time,
                stop_time=end_time
            )
        )
        output_message = "Searching for query '{}'".format(query)
        siemplify.LOGGER.info(f"Query: {query}")
        # Create search id or get existing id from result_value
        result_value = manager.run_query(query) if is_first_run else siemplify.parameters['additional_data']

        if manager.is_search_completed(result_value):
            query_results = manager.get_completed_search_query_result(result_value)
            status = EXECUTION_STATE_COMPLETED
            query_results_values = list(filter(lambda value: value, query_results.values()))

            if not query_results_values:
                result_value = False
                output_message = f'No results found for the query \"{query}\" in QRadar.'
            else:
                result_value = True
            for query_value in query_results_values:
                siemplify.result.add_result_json(query_results)
                output_message = f'Successfully retrieved results for the query \"{query}\" in QRadar.'
                siemplify.result.add_data_table("Results", construct_csv(query_value))
                break

    except Exception as error:
        output_message = f'Error executing action \"{SIMPLE_AQL_SEARCH_SCRIPT_NAME}\". Reason: {error}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- {} - Finished -----------------'.format(mode))
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == 'True'
    main(is_first_run)
