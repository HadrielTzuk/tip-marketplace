from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param
from VectraManager import VectraManager
from constants import (
    INTEGRATION_NAME,
    ENRICH_ENDPOINT_SCRIPT_NAME,
    ENRICHMENT_PREFIX
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_ENDPOINT_SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # Configuration.
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           input_type=unicode, is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Token",
                                            input_type=unicode, is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = u'true'
    output_message = u""
    json_results = {}
    successful_entities = []
    failed_entities = []
    duplicate_entities = []

    try:
        vectra_manager = VectraManager(api_root, api_token, verify_ssl=verify_ssl, siemplify=siemplify)
        suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS
                             or entity.entity_type == EntityTypes.HOSTNAME]

        for entity in suitable_entities:
            siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
            endpoints = vectra_manager.get_endpoint_details(entity.entity_type, entity.identifier)
            filtered_endpoints = [item for item in endpoints if item.name.lower() == entity.identifier.lower() or
                                  item.ip == entity.identifier]
            if filtered_endpoints:
                endpoint = filtered_endpoints[0]
                enrichment_data = endpoint.to_enrichment_data(prefix=ENRICHMENT_PREFIX)
                entity.additional_properties.update(enrichment_data)
                entity.is_enriched = True

                # JSON result
                json_results[entity.identifier] = endpoint.to_json()
                siemplify.result.add_entity_table(entity.identifier, endpoint.to_csv())
                siemplify.LOGGER.info(
                    u'Successfully enriched the following endpoint from Vectra: {}'.format(entity.identifier))
                successful_entities.append(entity)
                if len(filtered_endpoints) > 1:
                    duplicate_entities.append(entity)
            else:
                failed_entities.append(entity)

            siemplify.LOGGER.info(u"Finished processing entity {0}".format(entity.identifier))

        if successful_entities:
            siemplify.update_entities(successful_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            output_message += (u'Successfully enriched the following endpoints from Vectra: {}'.format(u"\n".join(
                [entity.identifier for entity in successful_entities])))

        if failed_entities:
            output_message += u"\n\n Action was not able to enrich the following endpoints from Vectra: {}".format(
                u"\n".join([entity.identifier for entity in failed_entities]))

        if duplicate_entities:
            output_message += u"\n\n Multiple matches were found in Vectra, taking first match for the following " \
                              u"entities: {}".format(u"\n".join([entity.identifier for entity in duplicate_entities]))

        if not successful_entities:
            output_message = u"No entities were enriched."
            result_value = u'false'

    except Exception as e:
        output_message = u"Error executing action \"Enrich Endpoint\". Reason: {}".format(e)
        result_value = u'false'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(u'----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        u"\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
