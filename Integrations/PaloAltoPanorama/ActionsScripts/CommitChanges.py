# coding=utf-8
from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from PanoramaManager import PanoramaManager
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
import sys
import json
from PanoramaConstants import (
    COMMIT_STATUS_FAILED,
    COMMIT_STATUS_FINISHED
)

SCRIPT_NAME = u"Panorama - CommitChanges"
PROVIDER_NAME = u"Panorama"


def query_operation_status(siemplify, palo_alto_manager):
    job_information = json.loads(siemplify.extract_action_param("additional_data"))

    job_id = job_information.get("job_id")
    status = EXECUTION_STATE_INPROGRESS
    siemplify.LOGGER.info(u"Checking commit status of job id: {}".format(job_id))
    commit_status, result, output_message = palo_alto_manager.check_commit_status(job_id=job_id)

    result_value = {
        "job_id": job_id
    }

    result_value = json.dumps(result_value)

    if commit_status == COMMIT_STATUS_FINISHED:

        if result == COMMIT_STATUS_FAILED:
            output_message = u"Action wasn't able to successfully commit changes. Details: {}".format(output_message)
            result_value = False
            status = EXECUTION_STATE_COMPLETED
        else:
            output_message = u"Successfully commited changes to Palo Alto Panorama"
            result_value = True
            status = EXECUTION_STATE_COMPLETED

    else:
        output_message = u"Waiting for commit job to finish..."

    return output_message, result_value, status


def start_operation(siemplify, palo_alto_manager, only_my_changes):
    status = EXECUTION_STATE_INPROGRESS
    siemplify.LOGGER.info("Committing changes")
    job_id = palo_alto_manager.CommitChanges(only_my_changes=only_my_changes)

    if not job_id:
        output_message = u"Action wasn't able to successfully commit changes."
        result_value = False
        status = EXECUTION_STATE_COMPLETED

    else:
        output_message = u"Changes commited to Palo Alto Panorama, checking the commit status..."
        result_value = {
            "job_id": job_id
        }

        result_value = json.dumps(result_value)

    return output_message, result_value, status


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    mode = u"Main" if is_first_run else u"Check changes"

    siemplify.LOGGER.info("----------------- {} - Param Init -----------------".format(mode))

    # Configuration.
    server_address = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Api Root")
    username = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Username")
    password = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Verify SSL",
                                             default_value=True, input_type=bool)

    siemplify.LOGGER.info("----------------- {} - Started -----------------".format(mode))
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        only_my_changes = extract_action_param(siemplify, param_name=u"Only My Changes", default_value=True,
                                               input_type=bool,
                                               is_mandatory=True, print_value=True)

        palo_alto_manager = PanoramaManager(server_address, username, password, verify_ssl, siemplify.run_folder)

        if is_first_run:
            output_message, result_value, status = start_operation(siemplify=siemplify,
                                                                   palo_alto_manager=palo_alto_manager,
                                                                   only_my_changes=only_my_changes)
        else:
            output_message, result_value, status = query_operation_status(siemplify=siemplify,
                                                                          palo_alto_manager=palo_alto_manager)

    except Exception as e:
        output_message = u'Error executing action {}. Reason: {}'.format(SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- {} - Finished -----------------".format(mode))
    siemplify.LOGGER.info(
        u'\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == 'True'
    main(is_first_run)
