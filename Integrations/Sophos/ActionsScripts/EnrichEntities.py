from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SophosManager import SophosManager
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, ENRICH_ENTITIES_SCRIPT_NAME, ISOLATED
from utils import get_entity_original_identifier


SUPPORTED_ENTITY_TYPES = [EntityTypes.HOSTNAME, EntityTypes.ADDRESS, EntityTypes.FILEHASH]
ENRICHMENT_PREFIX = "Sophos"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_ENTITIES_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True, input_type=unicode)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Client ID",
                                            is_mandatory=True, input_type=unicode)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Client Secret",
                                                is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    create_insights = extract_action_param(siemplify, param_name="Create Insights", default_value=True,
                                           print_value=True, input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    successful_entities, failed_entities, json_results = [], [], {}
    result_value = True
    suitable_entities = [entity for entity in siemplify.target_entities if
                         entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        manager = SophosManager(api_root=api_root, client_id=client_id, client_secret=client_secret,
                                verify_ssl=verify_ssl, test_connectivity=True)

        for entity in suitable_entities:
            siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))

            try:
                if entity.entity_type != EntityTypes.FILEHASH:
                    endpoint = manager.find_entities(entity_identifier=get_entity_original_identifier(entity),
                                                     entity_type=entity.entity_type)

                    if endpoint:
                        endpoint.is_isolated = True if manager.check_isolation_status(endpoint_id=endpoint.scan_id) \
                                                       == ISOLATED else False
                        entity.additional_properties.update(endpoint.to_enrichment_data(prefix=ENRICHMENT_PREFIX))
                        json_results[entity.identifier] = endpoint.to_enrichment_json()
                        entity.is_enriched = True
                        successful_entities.append(entity)
                        if create_insights:
                            siemplify.add_entity_insight(entity, endpoint.to_insight())
                        siemplify.result.add_entity_table(entity.identifier, construct_csv([endpoint.to_csv()]))
                    else:
                        failed_entities.append(entity.identifier)
                else:
                    filehash = manager.get_blocked_items(entity.identifier)
                    if filehash:
                        entity.additional_properties.update(filehash.to_enrichment_data(prefix=ENRICHMENT_PREFIX))
                        json_results[entity.identifier] = filehash.to_json()
                        entity.is_enriched = True
                        entity.is_suspicious = True
                        successful_entities.append(entity)
                        if create_insights:
                            siemplify.add_entity_insight(entity, filehash.to_insight())
                        siemplify.result.add_entity_table(entity.identifier, construct_csv([filehash.to_csv()]))
                    else:
                        failed_entities.append(entity.identifier)

            except Exception as e:
                failed_entities.append(entity.identifier)
                siemplify.LOGGER.error(u"An error occurred on entity {}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

            siemplify.LOGGER.info(u"Finished processing entity {}".format(entity.identifier))

        if successful_entities:
            output_message = u'Successfully enriched the following entities using information from ' \
                             u'{}: ' \
                             u'{}\n'.format(INTEGRATION_DISPLAY_NAME, ", ".join([entity.identifier for entity in
                                                                                 successful_entities]))
            siemplify.update_entities(successful_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            if failed_entities:
                output_message += u'Action wasn\'t able to enrich the following entities using information from ' \
                                  u'{}: {}\n'.format(INTEGRATION_DISPLAY_NAME, ", ".join(failed_entities))
        else:
            output_message = "None of the provided entities were enriched."
            result_value = False

    except Exception as e:
        output_message = u'Error executing action "{}". Reason: {}'.format(ENRICH_ENTITIES_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value,
                                                                                           output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()