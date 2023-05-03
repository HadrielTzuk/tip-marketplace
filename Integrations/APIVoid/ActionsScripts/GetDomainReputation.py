from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from APIVoidManager import APIVoidManager, APIVoidNotFound, APIVoidInvalidAPIKeyError
from SiemplifyUtils import construct_csv, create_entity_json_result_object, \
    add_prefix_to_dict, get_domain_from_entity, dict_to_flat
from TIPCommon import extract_configuration_param, extract_action_param

INTEGRATION_NAME = u"APIVoid"
TRIGGER = u"APIVoid"
SCRIPT_NAME = u"APIVoid - Get domain Reputation"
INSIGHT_MSG = u"Country: {0}"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Root",
                                           is_mandatory=True, input_type=unicode)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Key",
                                          is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    threshold = extract_action_param(siemplify, param_name=u"Threshold", is_mandatory=True, default_value=0,
                                     print_value=True, input_type=int)
    create_insights = extract_action_param(siemplify, param_name=u"Create Insights", is_mandatory=True, input_type=bool)

    apivoid_manager = APIVoidManager(api_root, api_key, verify_ssl=verify_ssl)

    enriched_entities = []
    missing_entities = []
    failed_entities = []
    json_results = []
    output_message = ""
    action_state = EXECUTION_STATE_COMPLETED

    for entity in siemplify.target_entities:
        domain = None

        if entity.entity_type == EntityTypes.HOSTNAME:
            domain = entity.identifier

        elif entity.entity_type == EntityTypes.URL:
            domain = get_domain_from_entity(entity)

        if domain:
            try:
                reputation_obj = apivoid_manager.get_domain_reputation(entity.identifier)
                enrichment_data = dict_to_flat(reputation_obj.as_enrichment_data())

                if create_insights and enrichment_data.get("country_code"):
                    siemplify.add_entity_insight(
                        entity,
                        INSIGHT_MSG.format(enrichment_data.get("country_code")),
                        triggered_by=TRIGGER
                    )

                enrichment_data = add_prefix_to_dict(enrichment_data, "APIVoid")
                entity.additional_properties.update(enrichment_data)

                siemplify.result.add_entity_table(
                    entity.identifier,
                    construct_csv(reputation_obj.get_blacklist_report())
                )

                json_results.append(
                    create_entity_json_result_object(
                        entity.identifier,
                        reputation_obj.as_json()
                    )
                )

                if int(reputation_obj.as_json().get("blacklists", {}).get(
                        "detections")) > int(threshold):
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
                siemplify.LOGGER.error(
                    "An error occurred on entity: {}.\n{}.".format(
                        entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)

    if enriched_entities:
        entities_names = [entity.identifier for entity in enriched_entities]

        output_message += 'APIVoid: Fetched reputation for the following entities:\n{}\n'.format(
            '\n'.join(entities_names)
        )

        siemplify.update_entities(enriched_entities)

    if failed_entities:
        output_message += 'An error occurred on the following entities:\n{}\n'.format(
            '\n'.join([entity.identifier for entity in failed_entities])
        )
        action_state = EXECUTION_STATE_FAILED

    if missing_entities:
        output_message += 'No reputation found for the following entities:\n{}'.format(
            '\n'.join([entity.identifier for entity in missing_entities])
        )

    if not missing_entities and not failed_entities and not enriched_entities:
        output_message = "APIVoid: No entities were enriched."

    siemplify.result.add_result_json(json_results)
    siemplify.end(output_message, 'true', action_state)


if __name__ == '__main__':
    main()
