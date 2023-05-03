from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from FalconSandboxManager import FalconSandboxManager, FalconSandboxAnalysisReportError, FalconSandboxInvalidCredsError
import sys
import base64
import json
from TIPCommon import extract_configuration_param, extract_action_param

SCRIPT_NAME = u'FalconSandbox - AnalyzeFile'
IDENTIFIER = u'FalconSandbox'


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    mode = u'Main' if is_first_run else u'QueryState'

    siemplify.LOGGER.info(u'----------------- {} - Param Init -----------------'.format(mode))

    # INIT INTEGRATION CONFIGURATION:
    server_address = extract_configuration_param(siemplify, provider_name=IDENTIFIER, param_name=u'Api Root')
    key = extract_configuration_param(siemplify, provider_name=IDENTIFIER, param_name=u'Api Key')

    #  INIT ACTION PARAMETERS:
    file_path = extract_action_param(siemplify, param_name=u'File Path', print_value=True)
    env_id = extract_action_param(siemplify, param_name=u'Environment', input_type=int, print_value=True)
    include_report = extract_action_param(siemplify, param_name=u'Include Report', input_type=bool, default_value=True, print_value=True)
    output_message = u''

    siemplify.LOGGER.info(u'----------------- {} - Started -----------------'.format(mode))

    try:
        manager = FalconSandboxManager(server_address, key)

        if is_first_run:
            job_id, sha256 = manager.submit_file(file_path, env_id)
        else:
            job_id, sha256 = json.loads(siemplify.parameters[u'additional_data'])

        query_output_message, result_value, status = handle(siemplify, manager, job_id, sha256,
                                                                                env_id, file_path, include_report)
        output_message += query_output_message

    except Exception as e:
        msg = u'General error performing action {}. {}'.format(SCRIPT_NAME, e)
        siemplify.LOGGER.error(msg)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = 0
        output_message += msg

    siemplify.LOGGER.info(u'----------------- {} - Finished -----------------'.format(mode))
    siemplify.LOGGER.info(
        u'\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, json.dumps(result_value),
                                                                           output_message))
    siemplify.end(output_message, json.dumps(result_value), status)


def handle(siemplify, manager, job_id, sha256, env_id, file_path, include_report):
    """
       Action handle
       :param siemplify: SiemplifyAction object
       :param manager: FalconSandboxManager object
       :param job_id: The job id
       :param sha256: The sha256 of the file
       :param env_id: Environment id
       :param file_path: File path
       :param include_report: {bool} True if to include report attachment of the scan, otherwise False
       :return: {output message, json result, execution state}
    """
    max_threat_score = 0
    output_message = u""
    job_state = manager.get_job_state(job_id)
    siemplify.LOGGER.info(json.dumps(job_state))
    if not job_state.get('is_job_completed'):
        output_message = u'Job {} in progress.'.format(job_id)
        siemplify.LOGGER.info(output_message)
        return output_message, (job_id, sha256), EXECUTION_STATE_INPROGRESS

    siemplify.LOGGER.info(u'Job {} is completed.'.format(job_id))

    if not job_state.get('is_success'):
        output_message = u'Analysis completed with errors. {}'.format(json.dumps(job_state))
        siemplify.LOGGER.error(output_message)
        return output_message, max_threat_score, EXECUTION_STATE_FAILED

    reports = manager.get_scan_info(sha256, env_id)

    if reports.get('scanned_element') == "original":
    
        for index, report in enumerate(reports.get('scan_info'), 1):
        
            threat_score = report['threat_score']
            max_threat_score = max(threat_score, max_threat_score)

            siemplify.LOGGER.info(u'Threat Score: {}'.format(threat_score))

            siemplify.LOGGER.info(u'Attaching JSON report')

            siemplify.result.add_json(
                u'Falcon Sandbox Report {} - {} - Environment {}'.format(
                    index, file_path, env_id),
                json.dumps(report))
        
        if include_report:
            try:
                mist_report_name, misp_report = manager.get_report(job_id, type=u'misp')
        
                siemplify.result.add_attachment(
                    u'Falcon Sandbox Misp Report',
                    mist_report_name,
                    base64.b64encode(misp_report)
                )
                siemplify.result.add_result_json(json.dumps(reports.get("scan_info")))
            except FalconSandboxInvalidCredsError:
                output_message += u"Action wasn't able to fetch entity reports due to permission issues related to the API Key. Please " \
                                  u"validate your API key or disable \"Include Report\" parameter.\n\n"
       
    elif reports.get('scanned_element') == "child":
        
        report = reports.get('scan_info')

        max_threat_score = report['threat_score']

        siemplify.LOGGER.info(u'Threat Score: {}'.format(max_threat_score))

        siemplify.LOGGER.info(u'Attaching JSON report')

        siemplify.result.add_json(
            u'Falcon Sandbox Report {} - {} - Environment {}'.format(
                "1", file_path, env_id),
            json.dumps(report))
        
        #setting new job_id to be the child's ID
        if include_report:
            try:
                job_id = report.get('job_id')
        
                mist_report_name, misp_report = manager.get_report(job_id, type=u'misp')
        
                siemplify.result.add_attachment(
                    u'Falcon Sandbox Misp Report',
                    mist_report_name,
                    base64.b64encode(misp_report)
                )
                siemplify.result.add_result_json(json.dumps(report))
            except FalconSandboxInvalidCredsError:
                output_message += u"Action wasn't able to fetch entity reports due to permission issues related to the API Key. Please " \
                                  u"validate your API key or disable \"Include Report\" parameter.\n\n"

    output_message += u'Provided file is archive/container, which does not have an associated analysis report. Fetching child report of ' \
                      u'embedded file(s) instead.\n Analysis completed - {}.\nMax Threat Score: {}'.format(job_id, max_threat_score)

    return output_message, max_threat_score, EXECUTION_STATE_COMPLETED


if __name__ == '__main__':
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == u'True'
    main(is_first_run)
