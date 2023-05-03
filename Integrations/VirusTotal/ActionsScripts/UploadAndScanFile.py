import json
import socket
import sys
import os
import paramiko
import errno

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import InsightType
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from VTFileOperationManager import FileOperationManager
from VirusTotal import VirusTotalManager, VirusTotalInvalidAPIKeyManagerError, VirusTotalLimitManagerError

SCRIPT_NAME = u'VirusTotal - Upload files'
IDENTIFIER = u'VirusTotal'
INSIGHT_CREATOR = u'Siemplify_System'
INSIGHT_TITLE = u'File {0} found as suspicious.'
ENTITY_TYPE = u'Entity Insight'
INSIGHT_SEVERITY_WARN = 1

THRESHOLD = 3


def start_operation(siemplify, manager, file_manager, file_paths, linux_server_address, linux_user, linux_password):
    """
    Main UploadAndScanFile action
    :param siemplify: SiemplifyAction object
    :param manager: VirusTotal object
    :param file_manager: FileOperationManager object
    :param file_paths: paths of files which will be checked
    :param linux_server_address: linux server address where files located
    :param linux_user: server user
    :param linux_password: server user password
    :return: {output message, not completed scans, execution state}
    """

    output_message = u''
    not_completed_scans = []
    failed_files = []
    limit_files = []

    for file_path in file_paths:
        # In case file is in remote linux send box
        try:
            if linux_server_address:
                # try:
                file_byte_array = file_manager.get_remote_unix_file_content(linux_server_address,
                                                                            linux_user,
                                                                            linux_password,
                                                                            file_path)

                scan_id = manager.upload_file(file_path, file_byte_array)

            else:
                scan_id = manager.upload_file(file_path)

            siemplify.LOGGER.info(u"Successfully submitted {}. Scan ID: {}".format(file_path, scan_id))

            not_completed_scans.append((file_path, scan_id))
            output_message += u'File was submitted successfully {}\n'.format(file_path)
        except paramiko.ssh_exception.AuthenticationException as e:
            err_msg = u'Your login or password is incorrect'
            siemplify.LOGGER.error(err_msg)
            siemplify.LOGGER.exception(e)
            return err_msg, u'false', EXECUTION_STATE_FAILED
        except (paramiko.ssh_exception.SSHException, socket.error) as e:
            err_msg = u'Timeout error. Please check your server address'
            siemplify.LOGGER.error(err_msg)
            siemplify.LOGGER.exception(e)
            return err_msg, u'false', EXECUTION_STATE_FAILED
        except IOError as e:
            if e.errno == errno.EACCES:
                err_msg = u"This file can not be accessible {}".format(file_path)
            else:
                err_msg = u"File is not found on the server {}".format(file_path)

            siemplify.LOGGER.info(u"Unable to submit {}. Reason: {}".format(file_path, err_msg))

            output_message += err_msg + '\n'
            siemplify.LOGGER.error(err_msg)
            failed_files.append(file_path)

        except VirusTotalInvalidAPIKeyManagerError as e:
            # Invalid key was passed - terminate action
            siemplify.LOGGER.error(u"Invalid API key was provided. Access is forbidden.")
            siemplify.LOGGER.exception(e)
            return u"Invalid API key was provided. Access is forbidden.", u"false", EXECUTION_STATE_FAILED

        except VirusTotalLimitManagerError as e:
            siemplify.LOGGER.error(u"API limit reached for {}.".format(file_path))
            siemplify.LOGGER.exception(e)
            limit_files.append(file_path)

        except Exception as e:
            err_msg = u"An error occurred on file {}".format(file_path)
            siemplify.LOGGER.error(err_msg)
            siemplify.LOGGER.exception(e)
            failed_files.append(file_path)
            output_message += err_msg + '\n'

    msg = u"{} files were submitted successfully and {} files were not submitted"\
        .format(len(not_completed_scans), len(failed_files + limit_files))
    siemplify.LOGGER.info(msg)
    output_message += '\n' + msg + '\n'

    if not_completed_scans:
        return output_message, json.dumps(([], not_completed_scans, failed_files, limit_files)), EXECUTION_STATE_INPROGRESS

    return output_message, u"false", EXECUTION_STATE_FAILED


def query_operation_status(siemplify, manager, completed_scans, not_completed_scans, threshold, failed_files, limit_files):
    """
    Main UploadAndScanFile action
    :param siemplify: SiemplifyAction object
    :param manager: VirusTotal object
    :param completed_scans: list of completed scans
    :param not_completed_scans: list of non-completed scans
    :param threshold: action init param
    :param failed_files: list of failed scans
    :param limit_files: list of scans that failed due to API limitation
    :return: {output message, result, execution state}
    """
    json_results = {}
    result_value = u"false"

    for file_path, scan_id in not_completed_scans:
        try:
            if not scan_id:
                continue

            siemplify.LOGGER.info(u"Fetching status of {} (scan {})".format(file_path, scan_id))
            report = manager.get_report_by_scan_id(scan_id)

            if not report:
                siemplify.LOGGER.info(u"File {} is still queued for analysis.".format(file_path))
                continue

            json_results[file_path] = report.to_json()
            # Scan is complete
            siemplify.LOGGER.info(
                u"File {} is ready.".format(file_path))
            completed_scans.append((file_path, scan_id, report.to_json()))

        except VirusTotalLimitManagerError:
            siemplify.LOGGER.info(u"API limit reached while checking if analysis of {} has completed.".format(file_path))
            limit_files.append(file_path)

        except Exception as e:
            siemplify.LOGGER.exception(e)
            raise

    # Remove from not_completed_scans the scans that were completed
    not_completed_scans = [(file_path, scan_id) for file_path, scan_id in not_completed_scans if
                           scan_id not in [scan[1] for scan in completed_scans]]

    # Remove from not_completed_scans the scans that failed due to API limit
    not_completed_scans = [(file_path, scan_id) for file_path, scan_id in not_completed_scans if
                           file_path not in limit_files]

    if not_completed_scans:
        # Some scans were not completed yet
        siemplify.LOGGER.info(u"Not all scans have completed. Waiting.")
        output_massage = u"Continuing... some of the requested items are still queued for analysis: {}".format(
            "\n".join([not_completed_scan[0] for not_completed_scan in
                       not_completed_scans]))
        return output_massage, json.dumps((completed_scans, not_completed_scans, failed_files, limit_files)), EXECUTION_STATE_INPROGRESS

    siemplify.LOGGER.info(u"All scans have completed. Collecting results.")

    for file_path, scan_id, report_json in completed_scans:
        try:
            siemplify.LOGGER.info(u"Collecting results for {} (scan ID: {})".format(file_path, scan_id))
            # Scan detections_information
            report = manager.get_hash_report(report_json)
            data_table = construct_csv(report.build_engine_csv())
            siemplify.LOGGER.info(u"Adding CSV report for {}".format(file_path))
            siemplify.result.add_data_table(u"{} Report".format(file_path), data_table)

            # Add comments of resource
            comments = manager.get_comments(file_path)
            siemplify.LOGGER.info(u"Found {} comments for {}.".format(len(comments), file_path))

            if comments:
                siemplify.LOGGER.info(u"Adding comments CSV table for {}.".format(file_path))
                comments_table = construct_csv([comment.to_csv() for comment in comments])
                siemplify.result.add_data_table(u"Comments to {}".format(file_path), comments_table)

            web_link = report.permalink
            siemplify.LOGGER.info(u"Adding report web link for {}".format(file_path))
            siemplify.result.add_link(u"{} Virus Total Web Link".format(file_path), web_link)

            # Check for risk
            if int(threshold) < report.positives:
                siemplify.LOGGER.info(u"{} was found risky by given threshold. Adding insight.".format(file_path))
                insight_message = u"VirusTotal - {} marked as malicious by {} of {} engines - Threshold set to " \
                                  u"- {} (if exceed threshold)".format(file_path,
                                                                       report.positives,
                                                                       report.total,
                                                                       threshold)

                siemplify.create_case_insight(INSIGHT_CREATOR,
                                              INSIGHT_TITLE.format(file_path),
                                              insight_message, u"",
                                              INSIGHT_SEVERITY_WARN, InsightType.Entity)
                result_value = u"true"

        except VirusTotalLimitManagerError:
            siemplify.LOGGER.error(u"API limit reached for {}".format(file_path))
            limit_files.append(file_path)

    # Remove from completed the scans that failed due to API limit
    completed_scans = [(file_path, scan_id, report_json) for file_path, scan_id, report_json in completed_scans if
                           file_path not in limit_files]

    for file_path, scan_id, report_json in completed_scans:
        json_results[file_path] = report_json

    output_massage = u""
    if completed_scans:
        output_massage += u"The following files were uploaded to VirusTotal for scan: {}\n"\
            .format(u"\n".join([completed_scan[0] for completed_scan in completed_scans]))
    if failed_files:
        output_massage += u"\nFailed to upload the following files: {}"\
            .format(u"\n".join(failed_files))

    if limit_files:
        output_massage += u"\nThe following files were not uploaded properly due to reaching API request limitation: {}" \
            .format(u"\n".join(limit_files))

    # add json
    siemplify.LOGGER.info(u"Adding JSON results.")
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    return output_massage, result_value, EXECUTION_STATE_COMPLETED


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    mode = u"Main" if is_first_run else u"QueryState"

    siemplify.LOGGER.info(u"----------------- {} - Param Init -----------------".format(mode))

    # INIT INTEGRATION CONFIGURATION:
    api_key = extract_configuration_param(siemplify, provider_name=IDENTIFIER, param_name=u"Api Key",
                                          input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=IDENTIFIER, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    #  INIT ACTION PARAMETERS:
    file_paths = extract_action_param(siemplify, param_name=u'File Paths', is_mandatory=False, input_type=unicode,
                                      print_value=True)
    linux_server_address = extract_action_param(siemplify, param_name=u'Linux Server Address', is_mandatory=False,
                                                input_type=unicode, print_value=False)
    linux_user = extract_action_param(siemplify, param_name=u'Linux User', is_mandatory=False,
                                      input_type=unicode, print_value=False)

    linux_password = extract_action_param(siemplify, param_name=u'Linux Password', is_mandatory=False,
                                          input_type=unicode, print_value=False)

    threshold = extract_action_param(siemplify, param_name=u'Threshold', is_mandatory=False,
                                     input_type=int, print_value=True, default_value=3)

    file_paths = [file_path.strip() for file_path in file_paths.split(u',')] if file_paths else []

    output_message = u""
    siemplify.LOGGER.info(u"----------------- {} - Started -----------------".format(mode))

    try:
        manager = VirusTotalManager(api_key, verify_ssl)
        file_manager = FileOperationManager()

        if is_first_run:

            output_message, result_value, status = start_operation(siemplify, manager, file_manager, file_paths,
                                                                   linux_server_address, linux_user, linux_password)
        else:
            completed_scans, not_completed_scans, failed_files, limit_entities = json.loads(siemplify.parameters[u"additional_data"])
            query_output_message, result_value, status = query_operation_status(siemplify, manager, completed_scans,
                                                                                not_completed_scans,
                                                                                threshold, failed_files,
                                                                                limit_entities)
            output_message += query_output_message

    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message += u"\n unknown failure"

    siemplify.LOGGER.info(u"----------------- {} - Finished -----------------".format(mode))
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == u'True'
    main(is_first_run)
