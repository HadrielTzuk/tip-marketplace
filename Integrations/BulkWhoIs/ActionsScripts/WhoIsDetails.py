from SiemplifyUtils import output_handler, flat_dict_to_csv, get_domain_from_entity
from SiemplifyDataModel import EntityTypes
# Imports
from SiemplifyAction import SiemplifyAction
from WhoisManager import WhoisManager
from SiemplifyUtils import add_prefix_to_dict, convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

import json
from urlparse import urlparse
# Consts

INTEGRATION_NAME = u"BulkWhoIS"
SCRIPT_NAME = u"BulkWhoIS - WhoIs Details"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    result_value = u"true"

    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL", default_value=False, input_type=bool)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key", is_mandatory=True, input_type=unicode)
    api_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Secret Key", is_mandatory=True, input_type=unicode)

    status = EXECUTION_STATE_COMPLETED
    entities_to_update = []
    json_results = {}
    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    try:
        whois = WhoisManager(api_key, api_secret, verify_ssl=verify_ssl)
        for entity in siemplify.target_entities:
            entity_to_scan = ""
            detail_object = None

            if entity.entity_type == EntityTypes.URL:
                entity_to_scan = get_domain_from_entity(entity)

            if entity.entity_type == EntityTypes.HOSTNAME and not entity.is_internal:
                url_without_schema = urlparse(entity.identifier)
                url_without_schema = url_without_schema.hostname #Check if the URL contains schema
                if url_without_schema:
                    entity_to_scan = url_without_schema
                else:
                    entity_to_scan = entity.identifier
                
            if entity.entity_type == EntityTypes.ADDRESS:                
                entity_to_scan = entity.identifier

            if entity_to_scan:
                try:
                    detail_object = whois.scan(entity_to_scan)
                except Exception as e:
                    # An error occurred - skip entity and continue
                    siemplify.LOGGER.error(u"An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                    siemplify.LOGGER.exception(e)

            if detail_object and detail_object.success == True:
                enrichment_dict = detail_object.to_enrichment_data()
                entity.additional_properties.update(enrichment_dict)
                entity.is_enriched = True
                entities_to_update.append(entity)

                entity_table = flat_dict_to_csv(detail_object.to_dict())
                siemplify.result.add_entity_table(entity.identifier, entity_table)

                # build json
                json_results[entity.identifier] = enrichment_dict

        if entities_to_update:
            entities_names = [entity.identifier for entity in entities_to_update]
            output_message = u"The following entities were enriched by Whois: \n" + '\n'.join(entities_names)
            siemplify.update_entities(entities_to_update)

        else:
            output_message = u"No entities were enriched."
    except Exception, e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Some errors occurred. Please check log"

    # add json
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
