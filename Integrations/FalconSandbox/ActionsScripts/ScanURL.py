from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from FalconSandboxManager import FalconSandboxManager
import sys
import base64
import json
from TIPCommon import extract_configuration_param, extract_action_param

SCRIPT_NAME = u'FalconSandbox - Scan URL'
IDENTIFIER = u'FalconSandbox'
SUPPORTED_ENTITIES = [EntityTypes.URL, EntityTypes.HOSTNAME]


def get_entity_by_identifier(target_entities, entity_identifier):
    for entity in target_entities:
        if entity.identifier == entity_identifier:
            return entity

    raise Exception(
        u"Entity with identifier {} was not found.".format(entity_identifier))


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
    threshold = extract_action_param(siemplify, param_name=u'Threshold', input_type=int, print_value=True)
    environment_name = extract_action_param(siemplify, param_name=u'Environment', input_type=unicode, print_value=True,
                                            default_value=u'Linux (Ubuntu 16.04, 64 bit)')
    env_id = FalconSandboxManager.get_environment_id_by_name(environment_name)
    siemplify.LOGGER.info(u"Environment ID: {}".format(env_id))
    siemplify.LOGGER.info(u'----------------- {} - Started -----------------'.format(mode))

    try:
        manager = FalconSandboxManager(server_address, key)

        if is_first_run:
            successful_jobs, failed_entities = first_run(siemplify, manager, env_id)

            if successful_jobs:
                output_message = u"Successfully submitted {} entities. Waiting for analysis".format(len(successful_jobs.keys()))
                result_value = json.dumps(
                    {u"in_progress_jobs": successful_jobs, u"init_failed_entities": failed_entities}
                )
                status = EXECUTION_STATE_INPROGRESS

            else:
                output_message = u"Failed to submit the following entities for analysis:\n   {}\nPlease check logs for more information.".format(
                    u"\n   ".join([entity for entity in failed_entities])
                )
                result_value = u"false"
                status = EXECUTION_STATE_FAILED

        else:
            output_message, result_value, status = handle(siemplify, manager, threshold)

    except Exception as e:
        siemplify.LOGGER.error(u"General error occurred while running action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"An error occurred while running action. Error: {}".format(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


def first_run(siemplify, manager, env_id):
    """
    Initiate the action - submit the URL/HOSTNAME entities to Falcon analysis
    :param siemplify: {SiemplifyAction} The Siemplify context of the action
    :param manager: {FalconSandboxManager} A manager instance
    :param env_id: {int} The env ID to submit the URLs with
    :return: {tuple} (successful_jobs, failed_entities)
    """
    successful_jobs = {}
    failed_entities = []

    for entity in siemplify.target_entities:
        try:
            if entity.entity_type not in SUPPORTED_ENTITIES:
                siemplify.LOGGER.info(u"Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                continue

            siemplify.LOGGER.info(u"Submitting {} for analysis.".format(entity.identifier))
            job_id, sha256 = manager.submit_url(entity.identifier, env_id)
            siemplify.LOGGER.info(u"Successfully submitted {}. Job ID: {}".format(entity.identifier, job_id))
            successful_jobs[job_id] = {
                u"entity_identifier": entity.identifier,
                u"sha256": sha256
            }

        except Exception as e:
            failed_entities.append(entity.identifier)
            siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
            siemplify.LOGGER.exception(e)

    return successful_jobs, failed_entities


def handle(siemplify, manager, threshold):
    """
        Handle the async part of the action
        :param siemplify: SiemplifyAction object
        :param manager: FalconSandboxManager object
        :param threshold: Threshold
        :return: {output message, json result, execution state}
    """
    additional_data = json.loads(siemplify.parameters[u'additional_data'])
    in_progress_jobs = additional_data[u'in_progress_jobs']
    init_failed_entities = additional_data[u'init_failed_entities']
    completed_jobs = additional_data.get(u'completed_jobs', {})
    failed_jobs = additional_data.get(u'failed_jobs', {})
    json_results = {}
    output_message = u""
    result_value = u"false"
    all_finished = True

    for job_id, job_info in in_progress_jobs.items():
        entity_identifier = job_info[u'entity_identifier']

        try:
            siemplify.LOGGER.info(u"Querying status of job {}, entity {}".format(job_id, entity_identifier))
            job_state = manager.get_job_state(job_id)

            if job_state[u'is_job_completed']:

                if job_state[u'is_success']:
                    siemplify.LOGGER.info(u"Job {} has completed successfully.".format(job_id))
                    completed_jobs[job_id] = job_info

                else:
                    siemplify.LOGGER.info(u"Job {} has completed with status: {}. Error: {}".format(
                        job_id, job_state[u'response'].get(u'state'),
                        job_state[u'response'].get(u'error'))
                    )
                    failed_jobs[job_id] = job_info

            else:
                siemplify.LOGGER.info(u"Job {} has not completed yet.".format(job_id))
                all_finished = False

        except Exception as e:
            output_message = u"Unable to get status for job {}. Aborting.".format(job_id)
            siemplify.LOGGER.error(output_message)
            siemplify.LOGGER.exception(e)

            return output_message, u"false", EXECUTION_STATE_FAILED

    if not all_finished:
        in_progress_jobs = {job_id: job_info for job_id, job_info in in_progress_jobs.items()
                            if job_id not in completed_jobs and job_id not in failed_jobs}
        total_jobs_count = len(in_progress_jobs.keys()) + len(completed_jobs.keys()) + len(failed_jobs.keys())

        siemplify.LOGGER.info(u"Jobs in progress: {}".format(u", ".join(in_progress_jobs.keys())))
        siemplify.LOGGER.info(u"Jobs completed: {}".format(u", ".join(completed_jobs.keys())))
        siemplify.LOGGER.info(u"Jobs failed: {}".format(u", ".join(failed_jobs.keys())))

        output_message = u"{} out of {} jobs are still in progress. Waiting for completion.".format(
            len(in_progress_jobs.keys()), total_jobs_count)

        result_value = json.dumps(
            {u"in_progress_jobs": in_progress_jobs, u"init_failed_entities": init_failed_entities,
             u"completed_jobs": completed_jobs, u"failed_jobs": failed_jobs}
        )

        return output_message, result_value, EXECUTION_STATE_INPROGRESS

    if not completed_jobs:
        siemplify.LOGGER.info(u"All jobs have failed.")
        output_message = u"Failed to scan the following entities:\n   {}\n\n".format(
            u"\n   ".join([job_info[u"entity_identifier"] for job_info in failed_jobs.values()])
        )
        return output_message, u"false", EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(
        u"All jobs have completed ({} successful, {} failed). Fetching reports.".format(len(completed_jobs.keys()),
                                                                                        len(failed_jobs.keys())))
    reports = manager.get_scan_info_by_job_id(completed_jobs.keys())

    successful_entities = []
    no_misp_report_entities = []
    failed_entities = []

    for report in reports:
        job_id = report[u'job_id']
        entity_identifier = completed_jobs[job_id][u"entity_identifier"]

        try:
            entity = get_entity_by_identifier(siemplify.target_entities, entity_identifier)
            json_results[entity_identifier] = report
            siemplify.LOGGER.info(u"Fetched report for job {}, entity: {}.".format(job_id, entity_identifier))

            av_detection_rate = report.get(u'av_detect') or 0
            if int(av_detection_rate) >= threshold:
                siemplify.LOGGER.info(u"Marking entity as suspicious and adding an insight.")
                entity.is_suspicious = True
                entity.is_enriched = True
                insight_msg = u"Falcon Sandbox - Entity was marked as malicious by av detection score {}. Threshold set to {}".format(
                    report.get(u'av_detect', 0), threshold)
                siemplify.add_entity_insight(entity, insight_msg, triggered_by=IDENTIFIER)

            siemplify.LOGGER.info(u"Fetching MISP report for job {}, entity: {}.".format(job_id, entity_identifier))

            try:
                mist_report_name, misp_report = manager.get_report_by_job_id(job_id, type=u'misp')
                siemplify.LOGGER.info(u"Fetched MISP report for job {}, entity: {}.".format(job_id, entity_identifier))

                try:
                    siemplify.result.add_entity_attachment(
                        u'Falcon Sandbox Misp Report - {} - Job {}'.format(entity_identifier, job_id),
                        mist_report_name,
                        base64.b64encode(misp_report)
                    )
                    successful_entities.append(entity)

                except EnvironmentError as e:
                    siemplify.LOGGER.error(e)
                    siemplify.LOGGER.error(u"MISP report won't be attached for job {}, entity: {}".format(job_id, entity_identifier))
                    no_misp_report_entities.append(entity)
            except Exception as e:
                no_misp_report_entities.append(entity)
                siemplify.LOGGER.error(u"Unable to fetch MISP report for job {}, entity: {}".format(job_id, entity_identifier))
                siemplify.LOGGER.exception(e)

        except Exception as e:
            failed_entities.append(entity_identifier)
            siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity_identifier))
            siemplify.LOGGER.exception(e)

    if successful_entities:
        output_message = u"Successfully fetched report the following entities:\n   {}\n\n".format(
            u"\n   ".join([entity.identifier for entity in successful_entities])
        )
        result_value = u"true"
        siemplify.update_entities(successful_entities)

    if no_misp_report_entities:
        output_message += u"Fetched scan report but failed to get MISP report for the following entities:\n   {}\n\n".format(
            u"\n   ".join([entity.identifier for entity in no_misp_report_entities])
        )
        result_value = u"true"
        siemplify.update_entities(no_misp_report_entities)

    if failed_entities:
        output_message += u"Failed to fetch reports for the following entities:\n   {}\n\n".format(
            u"\n   ".join([entity for entity in failed_entities])
        )

    if failed_jobs:
        output_message += u"Failed to scan the following entities:\n   {}\n\n".format(
            u"\n   ".join([job_info[u"entity_identifier"] for job_info in failed_jobs.values()])
        )

    if init_failed_entities:
        output_message += u"Failed to submit the following entities for analysis:\n   {}\nPlease check logs for more information.".format(
            u"\n   ".join([entity for entity in failed_entities])
        )

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    return output_message, result_value, EXECUTION_STATE_COMPLETED


if __name__ == '__main__':
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == u'True'
    main(is_first_run)
