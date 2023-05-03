from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

from ThreatQManager import ThreatQManager
from custom_exceptions import (
    ThreatQManagerException,
    ObjectNotFoundException,
    SourceObjectNotFoundException,
    DestinationObjectNotFoundException
)
from constants import (
    INTEGRATION_NAME,
    LINK_OBJECTS_SCRIPT
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LINK_OBJECTS_SCRIPT

    siemplify.LOGGER.info('=' * 10 + ' Main - Param Init ' + '=' * 10)

    server_address = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="ServerAddress",
        input_type=unicode
    )

    client_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="ClientId",
        input_type=unicode
    )

    username = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Username",
        input_type=unicode
    )

    password = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Password",
        input_type=unicode
    )

    source_object_type = extract_action_param(
        siemplify,
        param_name="Source Object Type",
        input_type=unicode,
        is_mandatory=True,
        print_value=True,
    )

    source_object_identifier = extract_action_param(
        siemplify,
        param_name="Source Object Identifier",
        input_type=unicode,
        is_mandatory=True,
        print_value=True,
    )

    source_indicator_type = extract_action_param(
        siemplify,
        param_name="Source Indicator Type",
        input_type=unicode,
        is_mandatory=False,
        print_value=True,
    )

    destination_object_type = extract_action_param(
        siemplify,
        param_name="Destination Object Type",
        input_type=unicode,
        is_mandatory=True,
        print_value=True,
    )

    destination_object_identifier = extract_action_param(
        siemplify,
        param_name="Destination Object Identifier",
        input_type=unicode,
        is_mandatory=True,
        print_value=True,
    )

    destination_indicator_type = extract_action_param(
        siemplify,
        param_name="Destination Indicator Type",
        input_type=unicode,
        is_mandatory=False,
        print_value=True,
    )

    siemplify.LOGGER.info('=' * 10 + ' Main - Started ' + '=' * 10)

    try:
        threatq_manager = ThreatQManager(server_address, client_id, username, password)

        linked_object = threatq_manager.link_objects(
            source_object_type=source_object_type,
            source_identifier=source_object_identifier,
            source_indicator_type=source_indicator_type,
            destination_object_type=destination_object_type,
            destination_identifier=destination_object_identifier,
            destination_indicator_type=destination_indicator_type,
        )

        siemplify.result.add_result_json(linked_object.to_json())

        output_message = 'Successfully linked objects in ThreatQ'
        result_value = True
        execution_status = EXECUTION_STATE_COMPLETED

    except ObjectNotFoundException as e:
        if isinstance(e, SourceObjectNotFoundException):
            output_message = u'{} object with value {} was not found in ThreatQ.'.format(source_object_type,
                                                                                         source_object_identifier)
        elif isinstance(e, DestinationObjectNotFoundException):
            output_message = u'{} object with value {} was not found in ThreatQ.'.format(destination_object_type,
                                                                                         destination_object_identifier)

        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
        execution_status = EXECUTION_STATE_COMPLETED

    except ThreatQManagerException as e:
        output_message = u'Action was not able to link objects in ThreatQ.'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
        execution_status = EXECUTION_STATE_COMPLETED

    except Exception as e:
        output_message = u'Error executing action Link Objects. Reason: {}'.format(e)
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
