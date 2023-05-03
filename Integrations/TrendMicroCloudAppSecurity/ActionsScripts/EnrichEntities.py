from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TrendMicroCloudAppSecurityManager import TrendMicroCloudAppSecurityManager
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    ENRICH_ENTITIES_ACTIONS,
    DISPLAY_INTEGRATION_NAME,
    SHA1_HASH_LENGTH,
    EMAIL_REGEX,
    ENRICHMENT_FIELD
)
from SiemplifyDataModel import EntityTypes
import re
from urllib.parse import urlparse


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_ENTITIES_ACTIONS
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                           param_name="API Root", is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                          param_name="API Key", is_mandatory=True, print_value=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""
    entities_blocked = []
    entities_not_blocked = []
    json_result = {
        "blocked_urls": [],
        "blocked_hashes": [],
        "blocked_senders": []
    }

    try:
        trend_manager = TrendMicroCloudAppSecurityManager(api_root=api_root, api_key=api_key, verify_ssl=verify_ssl)
        already_blocked_entities = trend_manager.get_blocked_entities()
        
        for entity in siemplify.target_entities: 
            if entity.entity_type == EntityTypes.URL:
                url_found = False
                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))
                
                url_without_schema = urlparse(entity.identifier)
                url_without_schema = url_without_schema.hostname
                
                if url_without_schema :  # the endpoint only supports valid URLs
                
                    for blocked_url in already_blocked_entities.urls:
                        blocked_url_hostname = urlparse(blocked_url).hostname
                        if not blocked_url_hostname: 
                            blocked_url = '//' + blocked_url
                        
                        blocked_url = urlparse(blocked_url).hostname
                        if url_without_schema.lower() == blocked_url:
                            url_found = True
                    
                    if url_found:
                        siemplify.LOGGER.info("Entity: {} was found in blocklist.".format(entity.identifier))
                        blocked_urls = json_result.get("blocked_urls")
                        blocked_urls.append(entity.identifier)
                        json_result["blocked_urls"] = blocked_urls
                        entity.is_suspicious = True
                        entities_blocked.append(entity)
                        entity.additional_properties.update(ENRICHMENT_FIELD)     
                    else:
                        entities_not_blocked.append(entity)
                        ENRICHMENT_FIELD["TMCAS_blocked"] = "False"
                        entity.additional_properties.update(ENRICHMENT_FIELD)  
                        siemplify.LOGGER.info("Entity: {} is currently not blocked in {}."
                                            .format(entity.identifier, DISPLAY_INTEGRATION_NAME))
                else:
                    siemplify.LOGGER.info("Entity type URL: {} is in incorrect format.".format(entity.identifier))
                    
            if entity.entity_type == EntityTypes.USER:
                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))

                if re.search(EMAIL_REGEX, entity.identifier.lower()):
                    if entity.identifier.lower() in map(str.lower, already_blocked_entities.senders):
                        siemplify.LOGGER.info("Entity: {} was found in blocklist.".format(entity.identifier))
                        blocked_senders = json_result.get("blocked_senders")
                        blocked_senders.append(entity.identifier)
                        json_result["blocked_senders"] = blocked_senders
                        entity.is_suspicious = True
                        entities_blocked.append(entity)
                        entity.additional_properties.update(ENRICHMENT_FIELD)
                    else:
                        entities_not_blocked.append(entity)
                        ENRICHMENT_FIELD["TMCAS_blocked"] = "False"
                        entity.additional_properties.update(ENRICHMENT_FIELD)  
                        siemplify.LOGGER.info("Entity: {} is currently not blocked in {}."
                                            .format(entity.identifier, DISPLAY_INTEGRATION_NAME))
                else:
                    siemplify.LOGGER.info("Entity type USER: {} is in incorrect format.".format(entity.identifier))

            if entity.entity_type == EntityTypes.FILEHASH and entity.entity_type:
                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))

                if len(entity.identifier) == SHA1_HASH_LENGTH:
                    if entity.identifier.lower() in map(str.lower, already_blocked_entities.hashes):
                        siemplify.LOGGER.info("Entity: {} was found in blocklist.".format(entity.identifier))
                        blocked_hashes = json_result.get("blocked_hashes")
                        blocked_hashes.append(entity.identifier)
                        json_result["blocked_hashes"] = blocked_hashes
                        entity.is_suspicious = True
                        entities_blocked.append(entity)
                        entity.additional_properties.update(ENRICHMENT_FIELD)
                    else:
                        entities_not_blocked.append(entity)
                        ENRICHMENT_FIELD["TMCAS_blocked"] = "False"
                        entity.additional_properties.update(ENRICHMENT_FIELD)  
                        siemplify.LOGGER.info("Entity: {} is currently not blocked in {}."
                                            .format(entity.identifier, DISPLAY_INTEGRATION_NAME))
                else:
                    siemplify.LOGGER.info("Entity type HASH: {} is in incorrect format. The action only "
                                        "supports SHA-1 hashes".format(entity.identifier))

        if not entities_blocked:
            result_value = False
            output_message += "No entities were enriched using information from {}.".format(DISPLAY_INTEGRATION_NAME)
        elif entities_blocked:
            output_message += "Successfully retrieved information about the following entities from {}: {}"\
                .format(DISPLAY_INTEGRATION_NAME, "\n".join([entity.identifier for entity in entities_blocked]))
            siemplify.update_entities(entities_blocked)
            siemplify.result.add_result_json({k: v for k, v in json_result.items() if v})

            if entities_not_blocked:
                siemplify.update_entities(entities_not_blocked)  
                output_message += "\nAction wasn't able to retrieve information about the following entities from {}:" \
                                " {}".format(DISPLAY_INTEGRATION_NAME, "\n".join([entity.identifier
                                                                                    for entity in entities_not_blocked]))

    except Exception as e:
        output_message += f'Error executing action {ENRICH_ENTITIES_ACTIONS}. Reason: {e}.'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        f'\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
