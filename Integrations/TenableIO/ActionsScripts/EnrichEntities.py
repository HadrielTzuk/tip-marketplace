from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, flat_dict_to_csv
from TenableIOManager import TenableIOManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, ENRICH_ENTITIES_SCRIPT_NAME, ENRICHMENT_PREFIX
from SiemplifyDataModel import EntityTypes


SUPPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_ENTITIES_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Secret Key",
                                             is_mandatory=True)
    access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Access Key",
                                             is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, is_mandatory=True, print_value=True)

    # Action parameters
    create_insight = extract_action_param(siemplify, param_name="Create Insight", input_type=bool, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    successful_entities = []
    json_results = {}
    assets = {}
    existing_entities = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        manager = TenableIOManager(api_root=api_root, secret_key=secret_key, access_key=access_key,
                                   verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)

        for entity in suitable_entities:
            for asset in manager.list_assets():
                if entity.identifier in asset.ipv4 or entity.identifier in asset.ipv6 or entity.identifier in asset.netbios_name:
                    existing_entities.append(entity)
                    assets[entity.identifier] = asset.id
                    break

        failed_entities = list(set(suitable_entities) - set(existing_entities))

        for entity in existing_entities:
            siemplify.LOGGER.info("\nStarted processing entity: {}".format(entity.identifier))

            try:
                asset = manager.get_asset(assets.get(entity.identifier))

                if asset:
                    successful_entities.append(entity)
                    json_results[entity.identifier] = asset.to_json()
                    entity.additional_properties.update(asset.to_enrichment_data(prefix=ENRICHMENT_PREFIX))
                    entity.is_enriched = True

                    siemplify.result.add_entity_table(
                        entity.identifier,
                        flat_dict_to_csv(asset.to_table())
                    )

                    if create_insight:
                        siemplify.add_entity_insight(
                            entity,
                            asset.as_insight(),
                            triggered_by=INTEGRATION_DISPLAY_NAME
                        )
                else:
                    failed_entities.append(entity)
            except Exception as e:
                siemplify.LOGGER.error(f"Failed processing entities: {entity.identifier}: Error is: {e}")
                failed_entities.append(entity)

            siemplify.LOGGER.info("Finished processing entity {}\n".format(entity.identifier))

        if successful_entities:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            siemplify.update_entities(successful_entities)
            output_message += "Successfully enriched the following entities using information from {}: \n{}"\
                .format(INTEGRATION_DISPLAY_NAME, "\n".join([entity.identifier for entity in successful_entities]))

        if failed_entities:
            output_message += "\nAction wasn't able to enrich the following entities using information from {}: \n{}"\
                .format(INTEGRATION_DISPLAY_NAME, "\n".join([entity.identifier for entity in failed_entities]))

        if not successful_entities:
            result = False
            output_message = "None of the provided entities were enriched."

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {ENRICH_ENTITIES_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{ENRICH_ENTITIES_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
