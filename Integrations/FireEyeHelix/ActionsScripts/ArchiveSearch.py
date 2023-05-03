from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from FireEyeHelixConstants import PROVIDER_NAME, ARCHIVE_SEARCH_SCRIPT_NAME
from TIPCommon import extract_configuration_param, extract_action_param
from FireEyeHelixManager import FireEyeHelixManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from FireEyeHelixExceptions import (
    FireEyeHelixJobNotFinishedException,
    FireEyeHelixJobPausedException,
)
import json
import sys


def start_operation(siemplify, manager, query, time_frame, limit, paused_count):
    """
    Start archive search query.
    :param siemplify: SiemplifyAction object.
    :param manager: FireEyeHelixManager object.
    :param query: {str} The query for the search.
    :param time_frame: {str} The time frame for the search.
    :param limit: {int} Maximum number of results to return.
    :param paused_count: {int} Specify how many times job was paused.
    :return: {tuple} output message, json result, execution state
    """
    job_id = manager.initialize_archive_search_query(query, time_frame)
    # If api return job data almost instantly here we will try to get data.
    return query_operation_status(siemplify, manager, job_id, query, limit, paused_count)


def query_operation_status(siemplify, manager, job_id, query, limit, paused_count):
    """
    Query archive search results.
    :param siemplify: SiemplifyAction object.
    :param manager: FireEyeHelixManager object.
    :param job_id: {int} The job id to fetch data.
    :param query: {str} The query for the search.
    :param limit: {int} Maximum number of results to return.
    :param paused_count: {int} Specify how many times job was paused.
    :return: {tuple} output message, json result, execution state
    """
    try:
        result = manager.get_query_result(job_id, limit)

        if result.contains_results():
            output_message = "Successfully returned results for the archive query \"{}\" in {}."\
                .format(query, PROVIDER_NAME)
            result_value = True
            siemplify.result.add_result_json(result.to_json())
        else:
            output_message = "No results were found for the archive query \"{}\".".format(query)
            result_value = False

        state = EXECUTION_STATE_COMPLETED

    except FireEyeHelixJobNotFinishedException:
        output_message = "Continuing processing query"
        result_value = json.dumps([job_id, paused_count])
        state = EXECUTION_STATE_INPROGRESS
    except FireEyeHelixJobPausedException:
        if paused_count < 3:
            paused_count += 1
            manager.resume_archive_search_query(job_id)
            output_message = "Archive search job was resumed"
            result_value = json.dumps([job_id, paused_count])
            state = EXECUTION_STATE_INPROGRESS
        else:
            output_message = "No results were found for the archive query \"{}\". " \
                             "Reason: archive search job was paused more than 3 times.".format(query)
            result_value = False
            state = EXECUTION_STATE_COMPLETED

    return output_message, result_value, state


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = ARCHIVE_SEARCH_SCRIPT_NAME
    mode = "Main" if is_first_run else "QueryState"

    siemplify.LOGGER.info("----------------- {} - Param Init -----------------".format(mode))

    # Init Integration Configurations
    api_root = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="API Root",
        is_mandatory=True
    )

    api_token = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="API Token",
        is_mandatory=True
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Verify SSL",
        is_mandatory=True,
        input_type=bool
    )

    # Init Action Parameters
    query = extract_action_param(siemplify, param_name='Query', is_mandatory=True, print_value=True)
    time_frame = extract_action_param(siemplify, param_name='Time Frame', is_mandatory=True, print_value=True)
    limit = extract_action_param(siemplify, param_name='Max Results To Return', is_mandatory=False,
                                 input_type=int, print_value=True)

    siemplify.LOGGER.info("----------------- {} - Started -----------------".format(mode))

    try:
        manager = FireEyeHelixManager(
            api_root=api_root,
            api_token=api_token,
            verify_ssl=verify_ssl,
            siemplify=siemplify
        )

        if is_first_run:
            paused_count = 0
            output_message, result_value, status = start_operation(siemplify, manager, query, time_frame, limit, paused_count)
        else:
            job_id, paused_count = json.loads(siemplify.parameters["additional_data"])
            output_message, result_value, status = query_operation_status(siemplify, manager, job_id, query, limit, paused_count)

    except Exception as e:
        siemplify.LOGGER.exception(e)
        output_message = "Error executing action \"Archive Search\". Reason: {}'".format(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- {} - Finished -----------------".format(mode))
    siemplify.LOGGER.info('Status: {}'.format(status))
    siemplify.LOGGER.info('Result: {}'.format(result_value))
    siemplify.LOGGER.info('Output Message: {}'.format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == u'True'
    main(is_first_run)