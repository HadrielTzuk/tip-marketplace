from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from IllusiveNetworksManager import IllusiveNetworksManager
from TIPCommon import extract_configuration_param, construct_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyDataModel import EntityTypes
from IllusiveNetworksExceptions import RateLimitException
from constants import (
    INTEGRATION_NAME,
    ENRICH_ENTITIES_ACTION,
    PRODUCT_NAME
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_ENTITIES_ACTION
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Root", is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Key", is_mandatory=True, print_value=False)
    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="CA Certificate File", is_mandatory=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""
    failed_entities = []
    json_results = {}
    entities_to_update = []

    scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.HOSTNAME]

    try:
        illusivenetworks_manager = IllusiveNetworksManager(api_root=api_root, api_key=api_key, ca_certificate=ca_certificate, verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)
        illusivenetworks_manager.test_connectivity()
        for entity in scope_entities:
            try:
                host_object = illusivenetworks_manager.enrich_entity(host_entity_name=entity.identifier)

                if not host_object.raw_data:
                    failed_entities.append(entity)
                    continue

                json_results[entity.identifier] = host_object.to_json()
                entity.is_enriched = True
                entity.additional_properties.update(host_object.as_enrichment_data())
                entities_to_update.append(entity)

                siemplify.result.add_entity_table(
                 '{}'.format(entity.identifier),
                 construct_csv(host_object.to_table())
            )

            except RateLimitException as e:
                raise
            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error(u"An error occurred on entity: {}".format(entity.identifier))
                siemplify.LOGGER.exception(e)


        if len(scope_entities) == len(failed_entities):
            output_message += "No entities were enriched."
            result_value = False

        else:
            if entities_to_update:
                siemplify.update_entities(entities_to_update)
                output_message += "Successfully enriched the following entities using {}:\n{}".format(PRODUCT_NAME,"\n".join([entity.identifier for entity in
                                                                                    entities_to_update]))

                siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            if failed_entities:
                output_message += "\nAction wasn't able to enrich the following entities using {}:\n{}".format(PRODUCT_NAME,
                "\n".join([entity.identifier for entity in
                            failed_entities]))

    except Exception as e:
        output_message += 'Error executing action {}. Reason: {}.'.format(ENRICH_ENTITIES_ACTION, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False


    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
