from SiemplifyUtils import output_handler, add_prefix_to_dict_keys, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

from ThreatQManager import ThreatQManager
from custom_exceptions import (
    ThreatQManagerException
)
from constants import (
    INTEGRATION_NAME,
    INTEGRATION_PREFIX,
    CREATE_INDICATOR_SCRIPT
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_INDICATOR_SCRIPT

    json_results = {}
    entities_to_update = []
    failed_entities = []
    output_messages = []

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

    indicator_type = extract_action_param(
        siemplify,
        param_name="Indicator Type",
        input_type=unicode,
        is_mandatory=True,
        print_value=True,
    )

    status = extract_action_param(
        siemplify,
        param_name="Status",
        input_type=unicode,
        is_mandatory=True,
        print_value=True,
    )

    description = extract_action_param(
        siemplify,
        param_name="Description",
        input_type=unicode,
        is_mandatory=False,
        print_value=True,
    )

    siemplify.LOGGER.info('=' * 10 + ' Main - Started ' + '=' * 10)

    try:
        threatq_manager = ThreatQManager(server_address, client_id, username, password)
        for entity in siemplify.target_entities:
            try:
                siemplify.LOGGER.info(u'Started processing entity: {}'.format(entity.identifier))
                indicator = threatq_manager.create_indicator(
                    value=entity.identifier,
                    indicator_type=indicator_type,
                    status=status,
                    description=description
                )

                if not indicator:
                    siemplify.LOGGER.info(u'Indicator {} was not created'.format(entity.identifier))
                    failed_entities.append(entity)
                    continue

                json_results[entity.identifier] = indicator.to_json()
                entity.additional_properties.update(
                    add_prefix_to_dict_keys(indicator.to_flat_dict(), INTEGRATION_PREFIX)
                )
                entities_to_update.append(entity)

            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error(u'Failed processing entity: {}'.format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if entities_to_update:
            siemplify.update_entities(entities_to_update)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            output_messages.append(
                u'Successfully created indicators in ThreatQ based on the following entities: {}'
                .format(u', '.join([entity.identifier for entity in entities_to_update]))
            )

            if failed_entities:
                output_messages.append(
                    u'Action was not able to create indicators in ThreatQ based on the following entities: {}'
                    .format(u', '.join([entity.identifier for entity in failed_entities]))
                )

            result_value = True

        else:
            output_messages.append('No indicators were created.')
            result_value = False

        output_message = '\n'.join(output_messages)
        execution_status = EXECUTION_STATE_COMPLETED

    except (ThreatQManagerException, Exception) as e:
        output_message = u'Error executing action \"Create Indicator\"." Reason: {}'.format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        execution_status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('=' * 10 + ' Main - Finished ' + '=' * 10)
    siemplify.LOGGER.info(
        u'Status: {}, Result Value: {}, Output Message: {}'
        .format(execution_status, result_value, output_message)
    )
    siemplify.end(output_message, result_value, execution_status)


if __name__ == '__main__':
    main()
