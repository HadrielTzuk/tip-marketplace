import json
import sys

from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from MicrosoftDefenderATPManager import MicrosoftDefenderATPManager, MicrosoftDefenderATPError, \
    MicrosoftDefenderATPValidationError

PROVIDER_NAME = u'MicrosoftDefenderATP'
SCRIPT_NAME = u'{} - Wait for Task Status'.format(PROVIDER_NAME)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Api Root",
        input_type=unicode,
        is_mandatory=True
    )

    client_id = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Client ID",
        input_type=unicode,
        is_mandatory=True
    )

    client_secret = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Client Secret",
        input_type=unicode,
        is_mandatory=True
    )

    tenant_id = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Azure Active Directory ID",
        input_type=unicode,
        is_mandatory=True
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Verify SSL",
        input_type=bool,
        is_mandatory=True,
        default_value=False
    )

    task_ids = extract_action_param(
        siemplify,
        param_name="Task IDs",
        input_type=unicode,
        is_mandatory=True,
    )

    task_ids = MicrosoftDefenderATPManager.convert_comma_separated_to_list(task_ids)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    try:
        microsoft_defender_atp = MicrosoftDefenderATPManager(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            resource=api_root,
            verify_ssl=verify_ssl
        )

        succeeded_tasks = []
        pending_tasks = []

        for task_id in task_ids:
            task = microsoft_defender_atp.get_machine_task_status(id=task_id)

            if task.is_succeeded:
                succeeded_tasks.append(task)
            elif task.is_pending or task.is_in_progress:
                pending_tasks.append(task)
            else:
                output_message = u'Task with ID {} finished with status {}'.format(task.id, task.status)
                result = u'false'
                status = EXECUTION_STATE_COMPLETED

                if succeeded_tasks:
                    siemplify.result.add_result_json([task.to_json() for task in succeeded_tasks])

                    siemplify.result.add_data_table(
                        title=u'Current Task Status:',
                        data_table=construct_csv([task.to_table() for task in succeeded_tasks])
                    )

                siemplify.end(output_message, result, status)

        if not pending_tasks:
            output_message = u'{} Tasks were awaited'.format(len(succeeded_tasks) if len(succeeded_tasks) else 'No')
            result = u'true'
            status = EXECUTION_STATE_COMPLETED
            siemplify.LOGGER.info(output_message)

            if succeeded_tasks:
                siemplify.result.add_result_json([task.to_json() for task in succeeded_tasks])

                siemplify.result.add_data_table(
                    title=u'Current Task Status:',
                    data_table=construct_csv([task.to_table() for task in succeeded_tasks])
                )
        else:
            output_message = u'{} tasks should be awaited'.format(len(pending_tasks))
            result = u'false'
            status = EXECUTION_STATE_INPROGRESS

    except MicrosoftDefenderATPError as e:
        output_message = u'Action didn\'t completed due to error: {}'.format(e)
        result = u'false'
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u'Status: {}'.format(status))
    siemplify.LOGGER.info(u'Result: {}'.format(result))
    siemplify.LOGGER.info(u'Output Message: {}'.format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
