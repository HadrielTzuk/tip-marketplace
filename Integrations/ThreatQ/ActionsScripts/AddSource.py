from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

from ThreatQManager import ThreatQManager
from custom_exceptions import (
    ThreatQManagerException,
    ObjectNotFoundException,
    ObjectCreateException
)
from constants import (
    INTEGRATION_NAME,
    ADD_SOURCE_SCRIPT
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_SOURCE_SCRIPT

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
        default_value=u"Adversary",
        is_mandatory=True,
        print_value=True,
    )

    object_identifier = extract_action_param(
        siemplify,
        param_name="Object Identifier",
        is_mandatory=True,
        print_value=True,
    )

    indicator_type = extract_action_param(
        siemplify,
        param_name="Indicator Type",
        default_value=u"ASN",
        is_mandatory=False,
        print_value=True,
    )

    source_name = extract_action_param(
        siemplify,
        param_name="Source Name",
        is_mandatory=True,
        print_value=True,
    )

    siemplify.LOGGER.info('=' * 10 + ' Main - Started ' + '=' * 10)

    try:
        threatq_manager = ThreatQManager(server_address, client_id, username, password)

        universal_object = threatq_manager.add_source_to_object(
            object_type=object_type,
            object_identifier=object_identifier,
            indicator_type=indicator_type,
            source_name=source_name
        )

        siemplify.result.add_result_json(universal_object.to_json())

        output_message = u'Successfully added source {} to {} object in ThreatQ'.format(source_name, object_type)
        result_value = True
        execution_status = EXECUTION_STATE_COMPLETED

    except ObjectNotFoundException as e:
        output_message = u'{} object with value {} was not found in ThreatQ.'.format(object_type, object_identifier)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
        execution_status = EXECUTION_STATE_COMPLETED

    except ObjectCreateException as e:
        output_message = u'Action was not able to add source {} to the ThreatQ object.'.format(source_name)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
        execution_status = EXECUTION_STATE_COMPLETED

    except (ThreatQManagerException, Exception) as e:
        output_message = u'Error executing action \"Add Source\". Reason: {}'.format(e)
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
