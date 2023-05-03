from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from AzureADIdentityProtectionManager import AzureADIdentityProtectionManager
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, ENRICH_ENTITIES_SCRIPT_NAME, PRINCIPAL_NAME, \
    DISPLAY_NAME
from UtilsManager import get_entity_original_identifier, is_valid_email


SUPPORTED_ENTITY_TYPES = [EntityTypes.USER]
ENRICHMENT_PREFIX = "AzureADIP"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_ENTITIES_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client Secret",
                                                is_mandatory=True)
    tenant_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Tenant ID",
                                            is_mandatory=True, print_value=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    create_insights = extract_action_param(siemplify, param_name="Create Insights", default_value=True,
                                           print_value=True, input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    successful_entities, failed_entities, json_results = [], [], {}
    result_value = True
    suitable_entities = [entity for entity in siemplify.target_entities if
                         entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        manager = AzureADIdentityProtectionManager(
            api_root=api_root,
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            verify_ssl=verify_ssl
        )
        manager.test_connectivity()

        for entity in suitable_entities:
            siemplify.LOGGER.info(f"Started processing entity: {entity.identifier}")

            try:
                filter_key = PRINCIPAL_NAME if is_valid_email(get_entity_original_identifier(entity)) else DISPLAY_NAME
                entity_info = manager.get_user(username=entity.identifier, filter_key=filter_key)

                if entity_info:
                    entity.additional_properties.update(entity_info.to_enrichment_data(prefix=ENRICHMENT_PREFIX))
                    json_results[entity.identifier] = entity_info.to_json()
                    entity.is_enriched = True
                    successful_entities.append(entity)
                    if create_insights:
                        siemplify.add_entity_insight(entity, entity_info.to_insight())
                    siemplify.result.add_entity_table(entity.identifier, construct_csv([entity_info.to_csv()]))
                else:
                    failed_entities.append(entity.identifier)

            except Exception as e:
                failed_entities.append(entity.identifier)
                siemplify.LOGGER.error(f"An error occurred on entity {entity.identifier}")
                siemplify.LOGGER.exception(e)

            siemplify.LOGGER.info(f"Finished processing entity {entity.identifier}")

        if successful_entities:
            output_message = f'Successfully enriched the following entities using information from ' \
                             f'{INTEGRATION_DISPLAY_NAME}: ' \
                             f'{", ".join([entity.identifier for entity in successful_entities])}\n'
            siemplify.update_entities(successful_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            if failed_entities:
                output_message += f'Action wasn\'t able to enrich the following entities using information from ' \
                                  f'{INTEGRATION_DISPLAY_NAME}: {", ".join(failed_entities)}\n'
        else:
            output_message = "None of the provided entities were enriched."
            result_value = False

    except Exception as e:
        output_message = f'Error executing action "{ENRICH_ENTITIES_SCRIPT_NAME}". Reason: {e}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
