from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from utils import get_entity_original_identifier
from constants import (
    INTEGRATION_NAME,
    PRODUCT_NAME,
    GET_HASH_REPUTATION_SCRIPT_NAME,
)
from SentinelOneV2Factory import SentinelOneV2ManagerFactory

SUPPORTED_ENTITY_TYPES = [EntityTypes.FILEHASH]
REPUTATION_THRESHOLD_MAX_VALUE = 10


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_HASH_REPUTATION_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    reputation_threshold = extract_action_param(siemplify, param_name='Reputation Threshold',
                                                input_type=int, print_value=True)
    if reputation_threshold is not None and reputation_threshold > REPUTATION_THRESHOLD_MAX_VALUE:
        reputation_threshold = REPUTATION_THRESHOLD_MAX_VALUE
        siemplify.LOGGER.info(
            "'Reputation Threshold' parameter can not be more than {value}. Used {value} as max default value"
            .format(value=REPUTATION_THRESHOLD_MAX_VALUE))

    create_insight = extract_action_param(siemplify, param_name='Create Insight', input_type=bool, default_value=True,
                                          print_value=True)
    only_suspicious_insight = extract_action_param(siemplify, param_name='Only Suspicious Hashes Insight',
                                                   input_type=bool, print_value=True, default_value=True)

    success_entities, failed_entities, json_result = [], [], {}
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        manager = SentinelOneV2ManagerFactory().get_manager(api_root=api_root, api_token=api_token,
                                                            verify_ssl=verify_ssl,
                                                            force_check_connectivity=True)

        suitable_entities = [entity for entity in siemplify.target_entities if
                             entity.entity_type in SUPPORTED_ENTITY_TYPES]

        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)
            try:
                siemplify.LOGGER.info('Started Processing entity {}'.format(entity_identifier))

                hash = manager.get_hash_reputation(entity_identifier)
                if not hash:
                    failed_entities.append(entity_identifier)
                    continue

                siemplify.LOGGER.info('Found reputation for entity {}'.format(entity_identifier))
                if reputation_threshold is not None:
                    hash.reputation_threshold = reputation_threshold

                json_result[entity_identifier] = hash.to_json()

                if create_insight and not only_suspicious_insight:
                    siemplify.add_entity_insight(entity, hash.to_insight())
                elif only_suspicious_insight and hash.is_suspicious:
                    siemplify.add_entity_insight(entity, hash.to_insight())

                if hash.is_suspicious:
                    entity.is_suspicious = True

                # Enrich entity.
                entity.additional_properties.update(hash.to_enrichment_data())
                success_entities.append(entity)

                siemplify.LOGGER.info('Finished Processing entity {}'.format(entity_identifier))
            except Exception as e:
                failed_entities.append(entity_identifier)
                siemplify.LOGGER.error('Failed processing entity {}'.format(entity_identifier))
                siemplify.LOGGER.exception(e)

        if success_entities:
            siemplify.update_entities(success_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_result))
            output_message = 'Successfully returned reputation details for hashes:\n {}'.format(
                '\n '.join(map(get_entity_original_identifier, success_entities)))
        else:
            siemplify.LOGGER.info('Reputation details were not found for the hashes')
            output_message = 'Reputation details were not found for the hashes'
            result_value = False
        if failed_entities:
            output_message += '\nFailed to enrich hashes:\n {}'.format('\n '.join(failed_entities))

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(GET_HASH_REPUTATION_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
