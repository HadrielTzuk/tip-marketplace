from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from APIVoidManager import APIVoidManager, APIVoidNotFound, APIVoidInvalidAPIKeyError
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from SiemplifyUtils import convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv, add_prefix_to_dict

INTEGRATION_NAME = u"APIVoid"
SCRIPT_NAME = u"Get IP Reputation"
INSIGHT_MSG = u'Country: {}'
SUPPORTED_ENTITIES = [EntityTypes.ADDRESS]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Root",
                                           is_mandatory=True, input_type=unicode)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Key",
                                          is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    threshold = extract_action_param(siemplify, param_name=u"Threshold", is_mandatory=False,
                                     input_type=int, default_value=0, print_value=True)
    create_insights = extract_action_param(siemplify, param_name=u"Create Insights", is_mandatory=True, input_type=bool)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    result_value = u"true"
    enriched_entities = []
    missing_entities = []
    failed_entities = []
    json_results = {}
    status = EXECUTION_STATE_COMPLETED

    try:
        apivoid_manager = APIVoidManager(api_root, api_key, verify_ssl=verify_ssl)

        for entity in siemplify.target_entities:
            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info(u"Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue

                if entity.is_internal:
                    siemplify.LOGGER.info(u"Entity {} is internal. Skipping.".format(entity.identifier))
                    continue

                siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))

                reputation_obj = apivoid_manager.get_ip_reputation(entity.identifier)
                enrichment_data = reputation_obj.as_enrichment_data()

                if create_insights and enrichment_data.get(u"country_code"):
                    siemplify.LOGGER.info(
                        u"Entity {} country code: {}".format(entity.identifier, enrichment_data.get(u"country_code")))
                    siemplify.add_entity_insight(
                        entity,
                        INSIGHT_MSG.format(enrichment_data.get(u"country_code")),
                        triggered_by=INTEGRATION_NAME
                    )

                siemplify.LOGGER.info(u"Enriching entity {}".format(entity.identifier))
                enrichment_data = add_prefix_to_dict(enrichment_data, INTEGRATION_NAME)
                entity.additional_properties.update(enrichment_data)

                if reputation_obj.get_blacklist_report():
                    siemplify.LOGGER.info(u"Adding blacklist report for entity {}".format(entity.identifier))
                    siemplify.result.add_entity_table(
                        entity.identifier,
                        construct_csv(reputation_obj.get_blacklist_report())
                    )

                json_results[entity.identifier] = reputation_obj.as_json()

                if int(reputation_obj.as_json().get(u"blacklists", {}).get(u"detections", 0)) > int(threshold):
                    siemplify.LOGGER.info(u"Entity {} has {} detections. Marking as suspicious.".format(
                        entity.identifier,
                        int(reputation_obj.as_json().get(u"blacklists", {}).get(u"detections", 0))
                    ))
                    entity.is_suspicious = True

                entity.is_enriched = True
                enriched_entities.append(entity)

            except APIVoidNotFound as e:
                siemplify.LOGGER.error(e)
                missing_entities.append(entity)

            except APIVoidInvalidAPIKeyError as e:
                siemplify.LOGGER.error(e)
                raise APIVoidInvalidAPIKeyError(u"API key is invalid.")

            except Exception as e:
                failed_entities.append(entity)
                # An error occurred - skip entity and continue
                siemplify.LOGGER.error(u"An error occurred on entity: {}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if enriched_entities:
            output_message = u"APIVoid: Fetched reputation for the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in enriched_entities])
            )

            siemplify.update_entities(enriched_entities)

        else:
            output_message = u"APIVoid: No entities were enriched."
            result_value = u"false"

        if failed_entities:
            output_message += u"\n\nAn error occurred on the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in failed_entities])
            )

        if missing_entities:
            output_message += u"\n\nNo reputation was found for the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in missing_entities])
            )

    except Exception as e:
        siemplify.LOGGER.error(u"Action didn't complete due to error: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Action didn't complete due to error: {}".format(e)

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
