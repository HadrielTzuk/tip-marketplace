from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from PanoramaManager import PanoramaManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
import sys
import json
from PanoramaExceptions import JobNotFinishedException

SCRIPT_NAME = u"Panorama - SearchLogs"
PROVIDER_NAME = u"Panorama"
CSV_TABLE_NAME = u'{} Logs'


def start_operation(siemplify, manager, log_type, query):
    """
    Start operation action.
    :param siemplify: SiemplifyAction object.
    :param manager: PanoramaParser object.
    :param log_type: {str} Specify which log type should be returned.
    :param query: {str} Specify what query filter should be used to return logs.
    :return: {output message, json result, execution state}
    """
    # Parameters
    max_hours_backwards = extract_action_param(siemplify, param_name=u"Max Hours Backwards", print_value=True,
                                               input_type=int)
    max_logs_to_return = extract_action_param(siemplify, param_name=u"Max Logs to Return", print_value=True,
                                              input_type=int)

    try:
        job_id = manager.initialize_search_log_query(log_type, query, max_hours_backwards, max_logs_to_return)
        # since api return job data almost instantly here we will try to get data. If data is ready action will finish.
        return query_operation_status(siemplify, manager, job_id, log_type, query)

    except Exception as e:
        err_msg = u"Action wasn't able to list logs. Reason: {}".format(unicode(e))
        output_message = err_msg
        siemplify.LOGGER.error(err_msg)
        siemplify.LOGGER.exception(e)
        return output_message, False, EXECUTION_STATE_COMPLETED


def query_operation_status(siemplify, manager, job_id, log_type, query):
    """
    Query operation status.
    :param siemplify: SiemplifyAction object.
    :param manager: PanoramaParser object.
    :param job_id: {str} The job id to fetch data.
    :param log_type: {str} Specify which log type should be returned.
    :param query: {str} Specify what query filter should be used to return logs.
    :return: {output message, json result, execution state}
    """

    try:
        log_entities = manager.get_query_result(job_id)
        if log_entities:
            output_message = u"Successfully listed {} logs.  Used query: '{}'".format(log_type, query)
            result_value = True
            siemplify.result.add_result_json([log_entity.to_json() for log_entity in log_entities])
            siemplify.result.add_data_table(CSV_TABLE_NAME.format(log_type),
                                            construct_csv([log_entity.to_csv(log_type) for log_entity in log_entities]))
        else:
            output_message = u"No {0} logs were found. Used query: '{1}'".format(log_type, query)
            result_value = False
        state = EXECUTION_STATE_COMPLETED
    except JobNotFinishedException as e:
        output_message = u"Continuing processing query.... Progress {}%".format(e.progress)
        result_value = json.dumps(job_id)
        state = EXECUTION_STATE_INPROGRESS

    return output_message, result_value, state


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    mode = u"Main" if is_first_run else u"QueryState"

    siemplify.LOGGER.info(u"----------------- {} - Param Init -----------------".format(mode))

    # Configuration.
    api_root = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Api Root")
    username = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Username")
    password = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Verify SSL",
                                             default_value=True, input_type=bool)

    # Parameters
    log_type = extract_action_param(siemplify, param_name=u"Log Type", input_type=unicode, is_mandatory=True,
                                    print_value=True)
    query = extract_action_param(siemplify, param_name=u"Query", print_value=True)
    siemplify.LOGGER.info(u"----------------- {} - Started -----------------".format(mode))

    try:
        manager = PanoramaManager(api_root, username, password, verify_ssl)

        if is_first_run:
            output_message, result_value, status = start_operation(siemplify, manager, log_type, query)
        else:
            job_id = json.loads(siemplify.parameters[u"additional_data"])
            output_message, result_value, status = query_operation_status(siemplify, manager, job_id, log_type, query)

    except Exception as e:
        msg = u"Error executing action 'Search Logs'. Reason: {}".format(unicode(e))
        siemplify.LOGGER.error(msg)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = msg

    siemplify.LOGGER.info(u"----------------- {} - Finished -----------------".format(mode))
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == u'True'
    main(is_first_run)
