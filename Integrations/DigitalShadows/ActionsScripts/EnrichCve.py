from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param
from DigitalShadowsManager import DigitalShadowsManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SiemplifyDataModel import EntityTypes

# =====================================
#             CONSTANTS               #
# =====================================
INTEGRATION_NAME = u"DigitalShadows"
SCRIPT_NAME = u"DigitalShadows - EnrichCve"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key",
                                          input_type=unicode)

    api_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Secret",
                                             input_type=unicode)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    successful_entities = []
    failed_entities = []
    output_message = u""
    status = EXECUTION_STATE_COMPLETED
    result_value = u"true"
    json_results = {}
    try:
        manager = DigitalShadowsManager(api_key, api_secret)
        target_entities = [entity for entity in siemplify.target_entities if
                           entity.entity_type == EntityTypes.CVE]

        if target_entities:
            for entity in target_entities:
                if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                    siemplify.LOGGER.error(u"Timed out. execution deadline ({}) has passed".format(
                        convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                    status = EXECUTION_STATE_TIMEDOUT
                    break
                try:
                    cve_obj = manager.enrich_cve(entity.identifier)
                    successful_entities.append(entity)
                    json_results[entity.identifier] = cve_obj.to_json()
                    ## enrich the entity
                    siemplify.result.add_entity_table(entity.identifier, cve_obj.to_csv())
                    if cve_obj.links:
                        for link in cve_obj.links:
                            siemplify.result.add_entity_link(entity.identifier, link)
                    entity.additional_properties.update(cve_obj.to_enrichment_data())
                    entity.is_enriched = True
                    ## end enrichment
                    siemplify.LOGGER.info(u"Finished processing for entity {}".format(entity.identifier))
                except Exception as e:
                    failed_entities.append(entity.identifier)
                    siemplify.LOGGER.error(u"Failed processing entity {}".format(entity.identifier))
                    siemplify.LOGGER.exception(e)
            if successful_entities:
                siemplify.update_entities(successful_entities)
                siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
                output_message += u"Successfully enriched CVEs:\n {0}\n".format(
                    u"\n   ".join([entity.identifier for entity in successful_entities]))
                result_value = u"true"
            else:
                siemplify.LOGGER.info(u"\n No entities were processed.")
                output_message += u"No entities were processed.\n"
                result_value = u"false"
            if failed_entities:
                output_message += u"Failed to enrich CVEs:\n {0}".format("\n".join(failed_entities))
        else:
            output_message = u"No suitable entities found.\n"
            result_value = u"false"

    except Exception, e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Error executing action 'Enrich CVE'. Reason: {0}".format(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
