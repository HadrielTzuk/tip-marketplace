from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param, extract_action_param
from UtilsManager import get_entity_original_identifier, get_domain_from_entity
from VirusTotalManager import VirusTotalManager
from constants import PROVIDER_NAME, INTEGRATION_NAME, GET_RELATED_HASHES_SCRIPT_NAME, DEFAULT_RELATED_HASHES_LIMIT, \
    RELATED_RESULTS_TYPE
from exceptions import VirusTotalLimitReachedException


SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.URL, EntityTypes.FILEHASH, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_RELATED_HASHES_SCRIPT_NAME

    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool)
    # Parameters
    results = extract_action_param(siemplify, param_name="Results", default_value=RELATED_RESULTS_TYPE.get("combined"),
                                   print_value=False)
    max_returned_hashes = extract_action_param(siemplify, param_name="Max Hashes To Return", input_type=int,
                                               default_value=DEFAULT_RELATED_HASHES_LIMIT)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    hashes = {} if results == RELATED_RESULTS_TYPE.get("per_entity") else []
    suitable_entities_identifiers = {}
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITIES]

    for entity in suitable_entities:
        if entity.entity_type == EntityTypes.URL:
            suitable_entities_identifiers[get_domain_from_entity(get_entity_original_identifier(entity))] = entity
        else:
            suitable_entities_identifiers[get_entity_original_identifier(entity)] = entity

    request_items = [
        {
            'url_id': 'files',
            'url_type': 'bundled_files',
            'parser_method': 'get_hash_relation',
            'entity_types': [EntityTypes.FILEHASH],
            'name': 'bundled files'
        },
        {
            'url_id': 'files',
            'url_type': 'execution_parents',
            'parser_method': 'get_hash_relation',
            'entity_types': [EntityTypes.FILEHASH],
            'name': 'execution parents'
        },
        {
            'url_id': 'files',
            'url_type': 'similar_files',
            'parser_method': 'get_hash_relation',
            'entity_types': [EntityTypes.FILEHASH],
            'name': 'similar files'
        },
        {
            'url_id': 'ip_addresses',
            'url_type': 'communicating_files',
            'parser_method': 'get_hash_relation',
            'entity_types': [EntityTypes.ADDRESS],
            'name': 'communicating files'
        },
        {
            'url_id': 'ip_addresses',
            'url_type': 'referrer_files',
            'parser_method': 'get_hash_relation',
            'entity_types': [EntityTypes.ADDRESS],
            'name': 'referrer files'
        },
        {
            'url_id': 'domains',
            'url_type': 'communicating_files',
            'parser_method': 'get_hash_relation',
            'entity_types': [EntityTypes.URL],
            'name': 'communicating files'
        },
        {
            'url_id': 'domains',
            'url_type': 'referrer_files',
            'parser_method': 'get_hash_relation',
            'entity_types': [EntityTypes.URL],
            'name': 'referrer files'
        },
        {
            'url_id': 'domains',
            'url_type': 'communicating_files',
            'parser_method': 'get_hash_relation',
            'entity_types': [EntityTypes.HOSTNAME],
            'name': 'communicating files'
        },
        {
            'url_id': 'domains',
            'url_type': 'referrer_files',
            'parser_method': 'get_hash_relation',
            'entity_types': [EntityTypes.HOSTNAME],
            'name': 'referrer files'
        }
    ]

    try:
        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)

        try:
            for identifier, entity in suitable_entities_identifiers.items():
                siemplify.LOGGER.info("\nStarted processing entity: {}".format(entity.identifier))

                for data in request_items:
                    if entity.entity_type not in data.get('entity_types'):
                        continue

                    try:
                        related_items = manager.get_related_items(
                            url_id=data.get('url_id'),
                            entity=identifier,
                            url_type=data.get('url_type'),
                            parser_method=data.get('parser_method'),
                            limit=max_returned_hashes
                        )

                        if related_items:
                            if results == RELATED_RESULTS_TYPE.get("per_entity"):
                                hashes[entity.identifier] = list(set([related_item.file_hash
                                                                      for related_item in related_items]))
                            else:
                                hashes.extend([related_item.file_hash for related_item in related_items
                                               if related_item.file_hash not in hashes])

                                if len(hashes) >= max_returned_hashes:
                                    raise VirusTotalLimitReachedException("Related Hashes count reach to the Maximum "
                                                                          "Limit")
                        else:
                            siemplify.LOGGER.error(f"No {data.get('name')} were found for {entity.identifier}")

                    except VirusTotalLimitReachedException:
                        raise
                    except Exception as err:
                        siemplify.LOGGER.error(f"Failed processing entities: {entity.identifier}")
                        siemplify.LOGGER.exception(err)

                siemplify.LOGGER.info("Finished processing entity {}\n".format(entity.identifier))

        except VirusTotalLimitReachedException as err:
            siemplify.LOGGER.info(err)

        if hashes:
            if results == RELATED_RESULTS_TYPE.get("per_entity"):
                siemplify.result.add_result_json({"EntityResults": convert_dict_to_json_result_dict(hashes)})
            else:
                siemplify.result.add_result_json({"sha256_hashes": hashes[:max_returned_hashes]})

            output_message += "Successfully returned related hashes to the provided entities from {}."\
                .format(PROVIDER_NAME)
        else:
            output_message += "No related hashes were found to the provided entities from {}.".format(PROVIDER_NAME)
            result_value = False

    except Exception as err:
        output_message = "Error executing action “Get Related Hashes”. Reason: {}".format(err)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
