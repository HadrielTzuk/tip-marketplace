from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

from ThreatQManager import ThreatQManager
from custom_exceptions import (
    ThreatQManagerException,
    SourceObjectNotFoundException,
    DestinationObjectNotFoundException,
    RelatedObjectNotFoundException,
    ObjectNotFoundException
)
from constants import (
    INTEGRATION_NAME,
    LIST_RELATED_OBJECTS_SCRIPT
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_RELATED_OBJECTS_SCRIPT

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

    related_object_type = extract_action_param(
        siemplify,
        param_name="Related Object Type",
        input_type=unicode,
        is_mandatory=True,
        print_value=True,
    )

    limit = extract_action_param(
        siemplify,
        param_name="Max Related Objects To Return",
        input_type=int,
        is_mandatory=False,
        print_value=True,
    )

    siemplify.LOGGER.info('=' * 10 + ' Main - Started ' + '=' * 10)

    try:
        threatq_manager = ThreatQManager(server_address, client_id, username, password)

        related_objects = threatq_manager.get_related_objects(
            source_object_type=source_object_type,
            source_identifier=source_object_identifier,
            source_indicator_type=source_indicator_type,
            related_object_type=related_object_type,
            limit=limit
        )

        if related_objects:

            siemplify.result.add_result_json([related_object.to_json() for related_object in related_objects])
            siemplify.result.add_data_table(
                title=u'Related {} objects'.format(related_object_type),
                data_table=construct_csv([related_object.to_table() for related_object in related_objects])
            )

        output_message = 'Successfully listed related objects in ThreatQ.'
        result_value = True
        execution_status = EXECUTION_STATE_COMPLETED

    except SourceObjectNotFoundException as e:
        output_message = u'{} object with value {} was not found in ThreatQ.'.format(
            source_object_type,
            source_object_identifier
        )
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
        execution_status = EXECUTION_STATE_COMPLETED

    except RelatedObjectNotFoundException as e:
        output_message = u'No related {0} object were found.'.format(related_object_type)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
        execution_status = EXECUTION_STATE_COMPLETED

    except ObjectNotFoundException as e:
        output_message = unicode(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
        execution_status = EXECUTION_STATE_COMPLETED

    except ThreatQManagerException as e:
        output_message = u'Action was not able to list related objects in ThreatQ.'
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