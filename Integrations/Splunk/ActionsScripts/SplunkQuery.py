from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from SplunkManager import SplunkManager
from TIPCommon import construct_csv, extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, SPLUNK_QUERY_SCRIPT_NAME, DEFAULT_QUERY_LIMIT, FROM_TIME_DEFAULT, \
    TO_TIME_DEFAULT, QUERY_RESULTS_TABLE_NAME
import sys
import json
import time

MAX_ATTEMPT_FOR_JOB_RESULT = 3


def start_operation(siemplify, manager, query, result_fields, limit):
    from_time = extract_action_param(siemplify, param_name='Results From', default_value=FROM_TIME_DEFAULT,
                                     print_value=True)
    to_time = extract_action_param(siemplify, param_name='Results To', default_value=TO_TIME_DEFAULT, print_value=True)

    output_message = "Successfully started searching: {}".format(query)
    status = EXECUTION_STATE_INPROGRESS

    result_value = manager.search_job_for_query(query=query, limit=limit, from_time=from_time,
                                                to_time=to_time,
                                                fields=result_fields)

    return output_message, result_value, status


def wait_and_check_if_job_id_done(manager, sid):
    for i in range(MAX_ATTEMPT_FOR_JOB_RESULT):
        if manager.is_job_done(sid=sid):
            return True
        time.sleep(3)
    return False


def query_operation_status(siemplify, manager, result, query, result_fields, limit):
    status = EXECUTION_STATE_INPROGRESS
    result_value = result
    sid = result_value
    output_message = "Waiting for query {} to finish execution.".format(query)

    if wait_and_check_if_job_id_done(manager, sid):
        output_message, result_value, status = finish_operation(siemplify, manager, sid, query, result_fields, limit)

    return output_message, result_value, status


def finish_operation(siemplify, manager, sid, query, result_fields, limit):
    output_message = "No results were found for the query '{}' in {}".format(query, INTEGRATION_NAME)
    result_value = None
    status = EXECUTION_STATE_COMPLETED

    job_details = manager.get_job_results(sid, limit=limit)
    if job_details:
        result_json = [job_detail.to_json() for job_detail in job_details]
        table_result = [job_detail.to_filtered_csv(result_fields) for job_detail in job_details]
        siemplify.result.add_data_table(QUERY_RESULTS_TABLE_NAME, construct_csv(table_result))
        siemplify.result.add_result_json(result_json)
        result_value = json.dumps(result_json)

        output_message = "Successfully returned results for the query '{}' in {}".format(query, INTEGRATION_NAME)

    manager.delete_job(sid=sid)

    return output_message, result_value, status


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = SPLUNK_QUERY_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    url = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                      print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Username')
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Password')
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token')
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             print_value=True, input_type=bool)
    query = extract_action_param(siemplify, param_name='Query', print_value=True, is_mandatory=True)
    result_fields = extract_action_param(siemplify, param_name='Result fields', print_value=True)
    limit = extract_action_param(siemplify, param_name='Results count limit', input_type=int,
                                 default_value=DEFAULT_QUERY_LIMIT, print_value=True)

    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name='CA Certificate File')

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    output_message = ""
    result_value = None
    status = EXECUTION_STATE_INPROGRESS

    try:
        manager = SplunkManager(server_address=url, username=username, password=password, api_token=api_token,
                                ca_certificate=ca_certificate, verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)

        if is_first_run:
            output_message, result_value, status = start_operation(siemplify, manager=manager, query=query,
                                                                   result_fields=result_fields, limit=limit)

        if status == EXECUTION_STATE_INPROGRESS:
            result = result_value if result_value else extract_action_param(siemplify, param_name="additional_data",
                                                                            default_value='{}')
            output_message, result_value, status = query_operation_status(siemplify=siemplify, manager=manager,
                                                                          result=result, query=query,
                                                                          result_fields=result_fields, limit=limit)
    except Exception as e:
        output_message = 'Error executing action {}. Reason: {}'.format(SPLUNK_QUERY_SCRIPT_NAME, e)
        status = EXECUTION_STATE_FAILED
        result_value = None
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  results: {}\n  output_message: {}".format(status, result_value, output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)
