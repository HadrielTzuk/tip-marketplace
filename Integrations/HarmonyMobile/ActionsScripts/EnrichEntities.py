from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, flat_dict_to_csv
from HarmonyMobileManager import HarmonyMobileManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, ENRICH_ENTITIES_SCRIPT_NAME, ENRICHMENT_PREFIX
from SiemplifyDataModel import EntityTypes


SUPPORTED_ENTITY_TYPES = [EntityTypes.HOSTNAME]


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
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    # Action parameters
    create_insight = extract_action_param(siemplify, param_name="Create Insight", input_type=bool, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    successful_entities = []
    failed_entities = []
    json_results = {}
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        manager = HarmonyMobileManager(api_root=api_root, client_id=client_id, client_secret=client_secret,
                                       verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)

        devices = {device.name: device for device in manager.get_devices()
                   if device.name in [entity.identifier for entity in suitable_entities]}

        for entity in suitable_entities:
            siemplify.LOGGER.info("\nStarted processing entity: {}".format(entity.identifier))

            try:
                device = devices.get(entity.identifier)

                if device:
                    successful_entities.append(entity)
                    json_results[entity.identifier] = device.to_json()
                    entity.additional_properties.update(device.to_enrichment_data(prefix=ENRICHMENT_PREFIX))
                    entity.is_enriched = True

                    siemplify.result.add_entity_table(
                        entity.identifier,
                        flat_dict_to_csv(device.to_table())
                    )

                    if create_insight:
                        siemplify.add_entity_insight(
                            entity,
                            device.as_insight(),
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
