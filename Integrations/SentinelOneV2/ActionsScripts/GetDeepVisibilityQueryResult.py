import sys
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import DEEP_VISIBILITY_QUERY_EVENTS_DEFAULT_LIMIT
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SentinelOneV2Manager import DEEP_VISIBILITY_QUERY_FINISHED, DEEP_VISIBILITY_QUERY_RUNNING
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from constants import (
    INTEGRATION_NAME,
    GET_DEEP_VISIBILITY_QUERY_RESULT_SCRIPT_NAME,
    SENTINEL_ONE_EVENTS_TABLE_NAME,
)
from SentinelOneV2Factory import SentinelOneV2ManagerFactory, API_VERSION_2_0


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_DEEP_VISIBILITY_QUERY_RESULT_SCRIPT_NAME
    mode = 'Main' if is_first_run else 'QueryState'

    siemplify.LOGGER.info('----------------- {} - Param Init -----------------'.format(mode))

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info('----------------- {} - Started -----------------'.format(mode))

    query_id = extract_action_param(siemplify, param_name='Query ID', is_mandatory=True, print_value=True)
    limit = extract_action_param(siemplify, param_name='Limit', print_value=True, input_type=int,
                                 default_value=DEEP_VISIBILITY_QUERY_EVENTS_DEFAULT_LIMIT)
    limit = limit if limit > 0 else DEEP_VISIBILITY_QUERY_EVENTS_DEFAULT_LIMIT

    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        manager = SentinelOneV2ManagerFactory(API_VERSION_2_0).get_manager(api_root=api_root, api_token=api_token,
                                                                           verify_ssl=verify_ssl,
                                                                           force_check_connectivity=True)

        siemplify.LOGGER.info('Getting query status for query id {}'.format(query_id))
        query_status = manager.get_deep_visibility_query_status(query_id=query_id)
        siemplify.LOGGER.info('Successfully got query status {}'.format(query_status))

        if query_status == DEEP_VISIBILITY_QUERY_FINISHED:
            siemplify.LOGGER.info('Fetching events for query id {}'.format(query_id))
            events = manager.get_deep_visibility_query_events(query_id=query_id, limit=limit)

            if events:
                siemplify.result.add_data_table(SENTINEL_ONE_EVENTS_TABLE_NAME,
                                                construct_csv([event.as_csv() for event in events]))
                siemplify.result.add_result_json({'res_events': [event.to_base_json() for event in events]})
                output_message = 'Successfully found events for query: {}'.format(query_id)
            else:
                result_value = False
                siemplify.result.add_result_json({'res_events': []})
                output_message = 'No events were found'
        elif query_status == DEEP_VISIBILITY_QUERY_RUNNING:
            status = EXECUTION_STATE_INPROGRESS
            output_message = 'Received query status {}. Will check again later...'.format(query_status)
        else:
            raise Exception("status of the query - {}. Please run action 'Initialize Deep Visibility Query' again."
                            .format(query_status))

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(
            GET_DEEP_VISIBILITY_QUERY_RESULT_SCRIPT_NAME, e)
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
