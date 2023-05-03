import json
import sys
from FileManager import FileManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from VirusTotalManager import VirusTotalManager
from constants import PROVIDER_NAME, INTEGRATION_NAME, SUBMIT_FILE_SCRIPT_NAME, DEFAULT_COMMENTS_COUNT, COMPLETED, \
    COMMENTS_TABLE_TITLE, SIGMA_ANALYSIS_TITLE, REPORT_LINK_TITLE, INSIGHT_TITLE
from exceptions import ForceRaiseException


def start_operation(siemplify, manager):
    files_str = extract_action_param(siemplify, param_name="File Paths", is_mandatory=True, print_value=True)
    address = extract_action_param(siemplify, param_name="Linux Server Address", is_mandatory=False, print_value=True)
    username = extract_action_param(siemplify, param_name="Linux Username", is_mandatory=False, print_value=True)
    password = extract_action_param(siemplify, param_name="Linux Password", is_mandatory=False, print_value=True)
    files = [file.strip() for file in files_str.split(',') if file] if files_str else []

    failed_files, successful_files = [], []
    result_value = {
        'in_progress': {},
        'failed': {},
        'done': {}
    }
    output_message = ''
    status = EXECUTION_STATE_INPROGRESS
    file_bytes = None
    file_manager = FileManager(address, username, password) if address and username and password else None

    for file in files:
        try:
            # Get Submit URL
            submit_url = manager.get_upload_url()

            if file_manager:
                file_bytes = file_manager.get_remote_unix_file_content(file)

            analysis_id = manager.get_analysis(url=submit_url, file=file, file_bytes=file_bytes)
            # Fill json with every entity data
            result_value['in_progress'][file] = analysis_id
            successful_files.append(file)
        except Exception as err:
            if isinstance(err, ForceRaiseException):
                raise
            output_message = "Error executing action “Submit File”. Reason: {}".format(err)
            failed_files.append(file)
            result_value['failed'][file] = file
            siemplify.LOGGER.error(output_message)
            siemplify.LOGGER.exception(err)

    if successful_files:
        output_message += "Waiting for results for the following files: \n {} \n"\
            .format(PROVIDER_NAME, ', '.join(successful_files))
        result_value = json.dumps(result_value)

    if failed_files:
        output_message += "Action wasn’t able to return details about the following domains using {}: \n {} \n"\
            .format(PROVIDER_NAME, ', '.join(failed_files))

    if not successful_files:
        output_message = "No details about the files were retrieved."
        result_value = False
        status = EXECUTION_STATE_COMPLETED

    return output_message, result_value, status


def query_operation_status(siemplify, manager, task_analysis, threshold, percentage_threshold):
    completed_files = {}
    not_completed_files = {}

    for file, analysis_id in task_analysis['in_progress'].items():
        try:
            analysis_status, file_hash = manager.check_analysis_status(analysis_id=analysis_id, get_data=True)
            # Fill not completed and completed dicts with relevant items
            if analysis_status != COMPLETED:
                not_completed_files[file] = analysis_id
            else:
                completed_files[file] = file_hash

        except Exception as e:
            siemplify.LOGGER.error("An error occurred when checking status for file {}".format(file))
            siemplify.LOGGER.exception(e)

    # Remove completed filenames from in progress files
    for key in completed_files.keys():
        task_analysis['in_progress'].pop(key)
    # Update completed files with completed_files dict
    task_analysis['done'].update(completed_files)

    if task_analysis['in_progress']:
        output_message = 'Waiting for results for the following files: \n {} \n'\
            .format(', '.join(task_analysis['in_progress'].keys()))
        result_value = json.dumps(task_analysis)
        status = EXECUTION_STATE_INPROGRESS
    else:
        output_message, result_value, status = finish_operation(siemplify=siemplify, manager=manager,
                                                                completed_files=task_analysis['done'],
                                                                failed_files=task_analysis['failed'],
                                                                threshold=threshold,
                                                                percentage_threshold=percentage_threshold)

    return output_message, result_value, status


def finish_operation(siemplify, manager, completed_files, failed_files, threshold, percentage_threshold):
    whitelist_str = extract_action_param(siemplify, param_name="Engine Whitelist", is_mandatory=False, print_value=True)
    retrieve_comments = extract_action_param(siemplify, param_name="Retrieve Comments", is_mandatory=False,
                                             input_type=bool)
    retrieve_sigma_analysis = extract_action_param(siemplify, param_name="Retrieve Sigma Analysis", is_mandatory=False,
                                                   input_type=bool)
    max_returned_comments = extract_action_param(siemplify, param_name="Max Comments To Return", is_mandatory=False,
                                                 input_type=int, default_value=DEFAULT_COMMENTS_COUNT)
    whitelists = [item.strip() for item in whitelist_str.split(',') if item] if whitelist_str else []

    output_massage = ''
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    is_risky = False
    successful_files = []
    failed_files = list(failed_files.keys())
    not_found_engines = set()
    json_results = {}
    sigma_analysis = None
    comments = []

    for file, entity in completed_files.items():
        siemplify.LOGGER.info("Started processing file: {}".format(file))

        try:
            hash_data = manager.get_hash_data(file_hash=entity, report_link_suffix='hash')
            hash_data.set_supported_engines(whitelists)
            not_found_engines.update(set(hash_data.invalid_engines))

            if retrieve_comments:
                comments = manager.get_comments(url_type='files', entity=entity, limit=max_returned_comments)

            try:
                if retrieve_sigma_analysis:
                    sigma_analysis = manager.get_sigma_analysis(file_hash=entity)
            except Exception as err:
                siemplify.LOGGER.error("An error occurred on sigma analysis retrieve for {}".format(file))
                siemplify.LOGGER.exception(err)

            if threshold:
                if hash_data.threshold >= int(threshold):
                    is_risky = True
            else:
                if int(hash_data.percentage_threshold) >= percentage_threshold:
                    is_risky = True

            # Add case wall table for entity
            siemplify.result.add_data_table(title="Results: {}".format(file), data_table=construct_csv(hash_data.to_table()))
            # Fill json with every entity data
            json_results[file] = hash_data.to_json(comments=comments)
            # Create case wall table for comments
            if comments:
                siemplify.result.add_data_table(
                    title=COMMENTS_TABLE_TITLE.format(file),
                    data_table=construct_csv([comment.to_table() for comment in comments]))

            if sigma_analysis and sigma_analysis.rule_matches:
                siemplify.result.add_data_table(
                    title=SIGMA_ANALYSIS_TITLE.format(file),
                    data_table=construct_csv(sigma_analysis.to_table()))

            if hash_data.report_link:
                siemplify.result.add_entity_link(REPORT_LINK_TITLE, hash_data.report_link)

            siemplify.create_case_insight(INTEGRATION_NAME, INSIGHT_TITLE.format(file),
                                          hash_data.to_insight(threshold or f"{percentage_threshold}%"),
                                          entity, 0, 0)

            successful_files.append(file)
            siemplify.LOGGER.info("Finished processing file: {}".format(file))

        except Exception as e:
            if isinstance(e, ForceRaiseException):
                raise
            failed_files.append(file)
            siemplify.LOGGER.error("An error occurred on file: {}".format(file))
            siemplify.LOGGER.exception(e)

    if successful_files:
        output_massage += "Successfully returned details about the following files using {}: \n {} \n"\
            .format(PROVIDER_NAME, ', '.join(successful_files))

    if failed_files:
        output_massage += "Action wasn’t able to return details about the following domains using {}: \n {} \n"\
            .format(PROVIDER_NAME, ', '.join(failed_files))

    if not_found_engines:
        output_massage += "The following whitelisted engines were not found in {}: \n{} \n" \
            .format(PROVIDER_NAME, ', '.join(not_found_engines))

    if not successful_files:
        output_massage = "No details about the files were retrieved."
        result_value = False

    if json_results:
        siemplify.result.add_result_json({
            'results': convert_dict_to_json_result_dict(json_results),
            'is_risky': is_risky
        })

    return output_massage, result_value, status


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = SUBMIT_FILE_SCRIPT_NAME

    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool)

    threshold = extract_action_param(siemplify, param_name="Engine Threshold", is_mandatory=False, input_type=int,
                                     print_value=True)
    percentage_threshold = extract_action_param(siemplify, param_name="Engine Percentage Threshold", is_mandatory=False,
                                                input_type=int, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    result_value = False
    status = EXECUTION_STATE_INPROGRESS

    try:
        if not threshold and not percentage_threshold:
            raise Exception(f"either \"Engine Threshold\" or \"Engine Percentage Threshold\" should be provided.")

        if percentage_threshold and (percentage_threshold > 100 or percentage_threshold < 0):
            raise Exception(f"value for the parameter \"Engine Percentage Threshold\" is invalid. Please check it. "
                  f"The value should be in range from 0 to 100")

        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)

        if is_first_run:
            output_message, result_value, status = start_operation(siemplify=siemplify, manager=manager)

        if status == EXECUTION_STATE_INPROGRESS:
            task_analysis_json = result_value if result_value else extract_action_param(siemplify,
                                                                                        param_name="additional_data",
                                                                                        default_value=result_value)
            output_message, result_value, status = query_operation_status(siemplify=siemplify, manager=manager,
                                                                          task_analysis=json.loads(task_analysis_json),
                                                                          threshold=threshold,
                                                                          percentage_threshold=percentage_threshold)

    except Exception as err:
        output_message = "Error executing action “Submit File”. Reason: {}".format(err)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == 'True'
    main(is_first_run)
