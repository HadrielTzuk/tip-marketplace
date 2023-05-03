from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

from ThreatQManager import ThreatQManager
from custom_exceptions import (
    ThreatQManagerException,
    ObjectCreateException
)
from constants import (
    INTEGRATION_NAME,
    CREATE_OBJECT_SCRIPT
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_OBJECT_SCRIPT

    siemplify.LOGGER.info('=' * 10 + ' Main - Param Init ' + '=' * 10)

    server_address = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="ServerAddress"
    )

    client_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="ClientId"
    )

    username = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Username"
    )

    password = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Password"
    )

    object_type = extract_action_param(
        siemplify,
        param_name="Object Type",
        default_value=u"Attack Pattern",
        is_mandatory=True,
        print_value=True,
    )

    value = extract_action_param(
        siemplify,
        param_name="Value",
        is_mandatory=True,
        print_value=True,
    )

    description = extract_action_param(
        siemplify,
        param_name="Description",
        is_mandatory=False,
        print_value=True,
    )

    siemplify.LOGGER.info('=' * 10 + ' Main - Started ' + '=' * 10)

    try:
        threatq_manager = ThreatQManager(server_address, client_id, username, password)

        new_object = threatq_manager.create_object(
            object_type=object_type,
            value=value,
            description=description
        )

        siemplify.result.add_result_json(new_object.to_json())

        output_message = u'Successfully created new {} object in ThreatQ'.format(object_type)
        result_value = True
        execution_status = EXECUTION_STATE_COMPLETED

    except ObjectCreateException as e:
        output_message = u'Action was not able to create new {} object in ThreatQ.'.format(object_type)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
        execution_status = EXECUTION_STATE_COMPLETED

    except (ThreatQManagerException, Exception) as e:
        output_message = u'Error executing action \"Create Object\". Reason: {}'.format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
        execution_status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info('=' * 10 + ' Main - Finished ' + '=' * 10)
    siemplify.LOGGER.info(
        u'Status: {}, Result Value: {}, Output Message: {}'
        .format(execution_status, result_value, output_message)
    )
    siemplify.end(output_message, result_value, execution_status)


if __name__ == '__main__':
    main()
