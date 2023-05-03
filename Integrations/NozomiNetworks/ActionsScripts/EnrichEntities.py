from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from NozomiNetworksManager import NozomiNetworksManager
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from NozomiNetworksConstants import (
    PROVIDER_NAME,
    ENRICH_ENTITIES_SCRIPT_NAME,
    ENRICHMENT_PREFIX
)

SUPPORTED_ENTITY_TYPES = [EntityTypes.HOSTNAME, EntityTypes.ADDRESS]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_ENTITIES_SCRIPT_NAME

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_messages = []
    json_results = {}
    successful_entities = []
    failed_entities = []
    duplicate_entities = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

        # Configurations
        api_root = extract_configuration_param(
            siemplify,
            provider_name=PROVIDER_NAME,
            param_name='API URL',
            is_mandatory=True,
            print_value=True
        )

        username = extract_configuration_param(
            siemplify,
            provider_name=PROVIDER_NAME,
            param_name='Username',
            is_mandatory=True,
            print_value=True
        )

        password = extract_configuration_param(
            siemplify,
            provider_name=PROVIDER_NAME,
            param_name='Password',
            is_mandatory=True,
            print_value=False
        )

        verify_ssl = extract_configuration_param(
            siemplify,
            provider_name=PROVIDER_NAME,
            param_name='Verify SSL',
            input_type=bool,
            is_mandatory=False,
            print_value=True
        )

        ca_certificate = extract_configuration_param(
            siemplify,
            provider_name=PROVIDER_NAME,
            param_name="CA Certificate File",
            is_mandatory=False,
            print_value=False
        )

        # Parameters
        additional_fields = extract_action_param(siemplify, param_name='Additional fields to add to enrichment',
                                                 default_value='', is_mandatory=False, print_value=True)

        siemplify.LOGGER.info("----------------- Main - Started -----------------")

        manager = NozomiNetworksManager(
            api_root=api_root,
            username=username,
            password=password,
            ca_certificate_file=ca_certificate,
            verify_ssl=verify_ssl,
            siemplify_logger=siemplify.LOGGER
        )

        for entity in suitable_entities:
            siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))
            results = manager.get_entity(entity.identifier, entity.entity_type)

            if results:
                entity_object = results[-1]
                if len(results) > 1:
                    siemplify.LOGGER.info(
                        'Multiple matches were found in Nozomi Guardian, taking the most recent match for the following'
                        ' entity: {}'.format(entity.identifier))
                    duplicate_entities.append(entity)

                enrichment_data = entity_object.to_enrichment_data(additional_fields=[field.strip() for field in
                                                                                      additional_fields.split(',')
                                                                                      if field.strip()],
                                                                   prefix=ENRICHMENT_PREFIX)
                entity.additional_properties.update(enrichment_data)
                entity.is_enriched = True

                # JSON result
                json_results[entity.identifier] = entity_object.to_json()
                siemplify.LOGGER.info(
                    'Successfully enriched the following entity in Nozomi Guardian: {}'.format(entity.identifier))
                successful_entities.append(entity)
            else:
                siemplify.LOGGER.info(
                    'Action was not able to find Nozomi Guardian information to enrich the following entity: {}'.format(
                        entity.identifier))
                failed_entities.append(entity)

            siemplify.LOGGER.info("Finished processing entity {}".format(entity.identifier))

        if successful_entities:
            siemplify.update_entities(successful_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            output_messages.append('Successfully enriched the following entities: {}'.format(
                "\n".join([entity.identifier for entity in successful_entities])))

        if duplicate_entities:
            output_messages.append("Multiple matches were found in Nozomi Guardian, taking the most recent match for "
                                   "the following entities: {}".format("\n".join([entity.identifier for entity in
                                                                                  duplicate_entities])))

        if failed_entities:
            output_messages.append("Action was not able to find Nozomi Guardian information to enrich the following "
                                   "entities: {}".format("\n".join([entity.identifier for entity in failed_entities])))

        output_message = '\n'.join(output_messages)

        if not successful_entities:
            output_message = "No entities were enriched."
            result_value = False

    except Exception as e:
        output_message = "Failed to execute \"Enrich Entities\" action! Error is: {}".format(e)
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
