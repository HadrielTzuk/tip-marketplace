from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from FalconSandboxManager import FalconSandboxManager, COMPLETED_STATUS, IN_QUEUE_STATUS, IN_PROGRESS_STATUS
from TIPCommon import extract_configuration_param, extract_action_param
import sys
import base64
import json


SCRIPT_NAME = u'Wait For Job and Fetch Report'
INTEGRATION_NAME = u'FalconSandbox'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Root",
                                           is_mandatory=True, input_type=unicode)
    key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Key",
                                           is_mandatory=True, input_type=unicode)

    #  INIT ACTION PARAMETERS:
    job_ids = extract_action_param(siemplify, param_name=u'Job ID', print_value=True, is_mandatory=True)
    job_ids = [job_id.strip() for job_id in job_ids.split(u",")]

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    completed_jobs = []
    related_jobs = []
    failed_related_jobs = []
    json_results = {}
    failed_jobs = []
    successful_jobs = []
    no_misp_report_jobs = []
    status = EXECUTION_STATE_COMPLETED
    result_value = u"false"
    all_finished = True
    output_message = u""

    try:
        manager = FalconSandboxManager(server_address, key)

        for job_id in job_ids:
            try:
                siemplify.LOGGER.info(u"Querying status of job {}".format(job_id))
                job_state = manager.get_job_state(job_id)

                if job_state[u'response'].get(u'related_reports', []):
                    siemplify.LOGGER.info(u"Found {} related jobs for job with id {}".format(
                        len(job_state[u'response'].get(u'related_reports', [])), job_id))
                    related_jobs.extend(job_state[u'response'].get(u'related_reports', []))

                if job_state[u'is_job_completed']:

                    if job_state[u'is_success']:
                        siemplify.LOGGER.info(u"Job {} has completed successfully.".format(job_id))
                        completed_jobs.append(job_id)

                    else:
                        siemplify.LOGGER.info(u"Job {} has completed with status: {}. Error: {}".format(
                            job_id, job_state[u'response'].get(u'state'),
                            job_state[u'response'].get(u'error'))
                        )
                        failed_jobs.append(job_id)

                else:
                    siemplify.LOGGER.info(u"Job {} has not completed yet.".format(job_id))
                    all_finished = False
                    break

            except Exception as e:
                output_message = u"Unable to get status for job {}.".format(job_id)
                siemplify.LOGGER.error(output_message)
                siemplify.LOGGER.exception(e)

                status = EXECUTION_STATE_FAILED
                result_value = u"false"

                siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
                siemplify.LOGGER.info(u"Status: {}:".format(status))
                siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
                siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
                siemplify.end(output_message, result_value, status)

        for job in related_jobs:
            job_id = job.get('report_id', u"")
            siemplify.LOGGER.info(u"Processing related job with id: {}".format(job_id))
            job_status = job.get('state', u"")
            if job_status not in [IN_QUEUE_STATUS, IN_PROGRESS_STATUS]:
                if job_status == COMPLETED_STATUS:
                    siemplify.LOGGER.info(u"Job {} has completed successfully.".format(job_id))
                    completed_jobs.append(job_id)
                else:
                    siemplify.LOGGER.info(u"Job {} has completed with status: {}. Error: {}".format(
                        job_id, job_status,
                        job.get(u'error', u''))
                    )
                    failed_related_jobs.append(job)
            else:
                siemplify.LOGGER.info(u"Job {} has not completed yet.".format(job_id))
                all_finished = False
                break

        if related_jobs and len(related_jobs) == len(failed_related_jobs):
            output_message = u"Error executing action \"{}\". Reason:\n{}".format(
                SCRIPT_NAME, u"\n".join([job.get(u'error', u'') for job in failed_related_jobs]))
            status = EXECUTION_STATE_FAILED
            result_value = u"false"

            siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
            siemplify.LOGGER.info(u"Status: {}:".format(status))
            siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
            siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
            siemplify.end(output_message, result_value, status)

        if not all_finished:
            output_message = u"Jobs are in progress. Waiting for completion."
            status = EXECUTION_STATE_INPROGRESS
            result_value = u"false"

            siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
            siemplify.LOGGER.info(u"Status: {}:".format(status))
            siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
            siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
            siemplify.end(output_message, result_value, status)

        if not completed_jobs:
            siemplify.LOGGER.info(u"All jobs have failed.")
            output_message = u"All jobs have failed."
            status = EXECUTION_STATE_FAILED
            result_value = u"false"

            siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
            siemplify.LOGGER.info(u"Status: {}:".format(status))
            siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
            siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
            siemplify.end(output_message, result_value, status)

        siemplify.LOGGER.info(
            u"All jobs have completed ({} successful, {} failed). Fetching reports.".format(len(completed_jobs),
                                                                                            (len(failed_jobs) +
                                                                                             len(failed_related_jobs))))
        reports = manager.get_scan_info_by_job_id(completed_jobs)

        for report in reports:
            job_id = report[u'job_id']
            json_results[job_id] = report
            siemplify.LOGGER.info(u"Fetched report for job {}.".format(job_id))
            siemplify.LOGGER.info(u"Fetching MISP report for job {}".format(job_id))

            try:
                mist_report_name, misp_report = manager.get_report_by_job_id(job_id, type=u'misp')
                siemplify.LOGGER.info(u"Fetched MISP report for job {}.".format(job_id))

                try:
                    siemplify.result.add_attachment(
                        u'Falcon Sandbox Misp Report - Job {}'.format(job_id),
                        mist_report_name,
                        base64.b64encode(misp_report)
                    )
                    successful_jobs.append(job_id)

                except EnvironmentError as e:
                    siemplify.LOGGER.error(e)
                    siemplify.LOGGER.error(u"MISP report won't be attached for job {}".format(job_id))
                    no_misp_report_jobs.append(job_id)

            except Exception as e:
                no_misp_report_jobs.append(job_id)
                siemplify.LOGGER.error(u"Unable to fetch MISP report for job {}".format(job_id))
                siemplify.LOGGER.exception(e)

        if successful_jobs:
            output_message = u"Successfully fetched report for the following jobs:\n{}\n\n".format(
                u"\n   ".join([job_id for job_id in successful_jobs])
            )
            result_value = u"true"

        if no_misp_report_jobs:
            output_message += u"Fetched scan report but failed to get MISP report for the following jobs:\n{}\n\n".format(
                u"\n   ".join([job_id for job_id in no_misp_report_jobs])
            )

        if failed_jobs:
            output_message += u"Failed to fetch report for the following jobs:\n{}\n\n".format(
                u"\n   ".join([job_id for job_id in failed_jobs])
            )

        if failed_related_jobs:
            output_message += u"Some of the related reports were not available. Here are the related " \
                              u"errors:\n{}\n".format(u"\n".join([job.get(u'error', u'') for job in
                                                                  failed_related_jobs]))

    except Exception as e:
        siemplify.LOGGER.error(u"General error occurred while running action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"An error occurred while running action. Error: {}".format(e)

    siemplify.result.add_result_json(json_results)
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
