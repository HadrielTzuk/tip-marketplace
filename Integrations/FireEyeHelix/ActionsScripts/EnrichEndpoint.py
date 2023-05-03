from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from FireEyeHelixManager import FireEyeHelixManager
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param
from FireEyeHelixConstants import (
    PROVIDER_NAME,
    ENRICH_ENDPOINT_SCRIPT_NAME,
    ENRICHMENT_PREFIX
)

SUPPORTED_ENTITY_TYPES = [EntityTypes.HOSTNAME]

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_ENDPOINT_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Configuration.
    api_root = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name='API Root',
        is_mandatory=True,
        print_value=True
    )

    api_token = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name='API Token',
        is_mandatory=True,
        print_value=False
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name='Verify SSL',
        input_type=bool,
        is_mandatory=True,
        print_value=True
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_messages = []
    json_results = {}
    successful_entities = []
    failed_entities = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        manager = FireEyeHelixManager(
            api_root=api_root,
            api_token=api_token,
            verify_ssl=verify_ssl,
            siemplify=siemplify
        )

        for entity in suitable_entities:
            siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))
            entity_object = manager.get_endpoint(entity.identifier)

            if entity_object:
                enrichment_data = entity_object.to_enrichment_data(prefix=ENRICHMENT_PREFIX)
                entity.additional_properties.update(enrichment_data)
                entity.is_enriched = True

                # JSON result
                json_results[entity.identifier] = entity_object.to_json()
                siemplify.LOGGER.info(
                    'Successfully enriched the following entity in FireEye Helix: {}'.format(entity.identifier))
                successful_entities.append(entity)
            else:
                failed_entities.append(entity)

            siemplify.LOGGER.info("Finished processing entity {}".format(entity.identifier))

        if successful_entities:
            siemplify.update_entities(successful_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            output_messages.append('Successfully enriched the following entities in FireEye Helix: {}'.format(
                "\n".join([entity.identifier for entity in successful_entities])))

        if failed_entities:
            output_messages.append("Action was not able to enrich the following entities in FireEye Helix: {}"\
                .format("\n".join([entity.identifier for entity in failed_entities])))

        output_message = '\n'.join(output_messages)

        if not successful_entities:
            output_message = "No entities were enriched."
            result_value = False

    except Exception as e:
        output_message = "Error executing action \"Enrich Endpoint\". Reason: {}".format(e)
        result_value = False
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()