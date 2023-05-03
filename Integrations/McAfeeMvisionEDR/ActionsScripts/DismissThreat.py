import sys

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from TIPCommon import extract_configuration_param, extract_action_param
from SiemplifyUtils import output_handler
from constants import (
    INTEGRATION_NAME,
    DISMISS_THREAT_SCRIPT_NAME
)
from McAfeeMvisionEDRManager import McAfeeMvisionEDRManager
from McAfeeMvisionEDRExceptions import (
    McAfeeMvisionEDRException,
    CaseNotFoundException,
    TaskFailedException,
    UnknownTaskStatusException
)
from SiemplifyAction import SiemplifyAction


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = DISMISS_THREAT_SCRIPT_NAME
    siemplify.LOGGER.info(u'----------------- Main - Param Init -----------------')

    # Integration Parameters
    api_root = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name=u'API Root',
        is_mandatory=True,
        input_type=unicode,
        print_value=True
    )

    username = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name=u'Username',
        is_mandatory=False,
        input_type=unicode,
        print_value=True
    )

    password = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name=u'Password',
        is_mandatory=False,
        input_type=unicode,
        print_value=False
    )

    client_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Client ID",
        input_type=unicode
    )

    client_secret = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Client Secret",
        input_type=unicode,
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name=u'Verify SSL',
        is_mandatory=True,
        input_type=bool,
        print_value=True
    )

    threat_id = extract_action_param(
        siemplify,
        param_name=u'Threat ID',
        is_mandatory=True,
        input_type=unicode,
        print_value=True
    )

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    try:
        client = McAfeeMvisionEDRManager(
            api_root=api_root,
            username=username,
            password=password,
            client_id=client_id,
            client_secret=client_secret,
            verify_ssl=verify_ssl
        )

        if is_first_run:
            siemplify.LOGGER.info(u'First run of the action, creating threat dismission task')
            task = client.create_dismiss_threat_task(threat_id)
            siemplify.LOGGER.info(u'Threat dismission task was created with ID {}'.format(task.id))
        else:
            task_id = extract_action_param(
                siemplify,
                param_name=u'additional_data',
                is_mandatory=True,
                input_type=int,
                print_value=True
            )
            siemplify.LOGGER.info(u'Extracting task id {} from the previous run'.format(task_id))
            task = client.get_task_status(task_id)

        if task.is_failed:
            raise TaskFailedException(u'Task with ID {} failed'.format(task.id))

        elif task.is_completed:
            output_message = u'Successfully dismissed threat with ID {}'.format(threat_id)
            is_success = u'true'
            status = EXECUTION_STATE_COMPLETED

        elif task.is_in_progress:
            output_message = u'Dismission task {} with threat ID {} in progress...'.format(task.id, threat_id)
            is_success = task.id
            status = EXECUTION_STATE_INPROGRESS

        else:
            raise UnknownTaskStatusException(
                u'Unknown status {} for threat dismission with id {}'
                .format(task.status, threat_id)
            )

        siemplify.LOGGER.info(output_message)

    except CaseNotFoundException as e:
        output_message = unicode(e)
        is_success = u'false'
        status = EXECUTION_STATE_COMPLETED
        siemplify.LOGGER.info(output_message)
    except (TaskFailedException, UnknownTaskStatusException) as e:
        output_message = u'Failed to dismiss threat with id {}'.format(threat_id)
        is_success = u'false'
        status = EXECUTION_STATE_COMPLETED
        siemplify.LOGGER.info(output_message)
    except (Exception, McAfeeMvisionEDRException) as e:
        output_message = u'Error executing action \"Dismiss Threat\". Reason: {}'.format(e)
        is_success = u'false'
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(u'----------------- Main - Finished -----------------')
    siemplify.end(output_message, is_success, status)


if __name__ == "__main__":
    first_run = len(sys.argv) < 3 or sys.argv[2] == u'True'
    main(first_run)
