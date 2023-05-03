from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from Siemplify import InsightSeverity, InsightType
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict, get_domain_from_entity
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from VirusTotalManager import VirusTotalManager
from constants import PROVIDER_NAME, INTEGRATION_NAME, GET_DOMAIN_DETAILS_SCRIPT_NAME, DEFAULT_COMMENTS_COUNT, \
    COMMENTS_TABLE_TITLE, REPORT_LINK_TITLE, WIDGET_THEME_MAPPING
from exceptions import ForceRaiseException


SUPPORTED_ENTITY_TYPES = [EntityTypes.URL, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_DOMAIN_DETAILS_SCRIPT_NAME

    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool)
    # Parameters
    threshold = extract_action_param(siemplify, param_name="Engine Threshold", is_mandatory=False, input_type=int,
                                     print_value=True)
    percentage_threshold = extract_action_param(siemplify, param_name="Engine Percentage Threshold", is_mandatory=False,
                                                input_type=int, print_value=True)
    whitelist_str = extract_action_param(siemplify, param_name="Engine Whitelist", is_mandatory=False, print_value=True)
    retrieve_comments = extract_action_param(siemplify, param_name="Retrieve Comments", is_mandatory=False,
                                             input_type=bool)
    max_returned_comments = extract_action_param(siemplify, param_name="Max Comments To Return", is_mandatory=False,
                                                 input_type=int, default_value=10)
    create_insight = extract_action_param(siemplify, param_name="Create Insight", is_mandatory=False,
                                          input_type=bool, default_value=True)
    only_suspicious_insight = extract_action_param(siemplify, param_name="Only Suspicious Entity Insight",
                                                   is_mandatory=False, input_type=bool, default_value=False)
    widget_theme = extract_action_param(siemplify, param_name="Widget Theme", print_value=True)
    fetch_widget = extract_action_param(siemplify, param_name="Fetch Widget", input_type=bool, default_value=True,
                                        print_value=True)
    whitelists = [item.strip() for item in whitelist_str.split(',') if item] if whitelist_str else []

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    successful_identifiers = []
    failed_entities = []
    json_results = {}
    global_is_risky = False
    not_found_engines = set()
    comments = []
    suitable_entities_domains = {}
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]
    for entity in suitable_entities:
        if entity.entity_type == EntityTypes.URL:
            suitable_entities_domains[get_domain_from_entity(entity)] = entity
        else:
            suitable_entities_domains[entity.identifier] = entity

    try:
        if not threshold and not percentage_threshold:
            raise Exception(f"either \"Engine Threshold\" or \"Engine Percentage Threshold\" should be provided.")

        if percentage_threshold and (percentage_threshold > 100 or percentage_threshold < 0):
            raise Exception(f"value for the parameter \"Engine Percentage Threshold\" is invalid. Please check it. "
                  f"The value should be in range from 0 to 100")

        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)

        for identifier, entity in suitable_entities_domains.items():
            siemplify.LOGGER.info("Started processing entity: {}".format(identifier))
            is_risky = False

            try:
                domain_data = manager.get_domain_data(domain=identifier, show_entity_status=True)
                domain_data.set_supported_engines(whitelists)
                not_found_engines.update(set(domain_data.invalid_engines))
                if retrieve_comments:
                    comments = manager.get_comments(url_type='domains', entity=identifier, limit=max_returned_comments,
                                                    show_entity_status=True)

                widget_link, widget_html = manager.get_widget(
                    identifier, show_entity_status=True, theme_colors=WIDGET_THEME_MAPPING.get(widget_theme)
                ) if fetch_widget else (None, None)

                domain_data.widget_link = widget_link
                domain_data.widget_html = widget_html
                domain_data.entity_type = entity.entity_type

                if threshold:
                    if domain_data.threshold >= int(threshold):
                        is_risky = True
                        global_is_risky = True
                        entity.is_suspicious = True
                else:
                    if int(domain_data.percentage_threshold) >= percentage_threshold:
                        is_risky = True
                        global_is_risky = True
                        entity.is_suspicious = True

                # Enrich entity
                entity.additional_properties.update(domain_data.to_enrichment_data())
                # Add case wall table for entity
                siemplify.result.add_entity_table(entity.identifier, construct_csv(domain_data.to_table()))
                # Fill json with every entity data
                json_results[identifier] = domain_data.to_json(comments=comments, widget_link=widget_link)
                json_results[identifier].update({"execution_status": "success"})

                # Create case wall table for comments
                if comments:
                    siemplify.result.add_data_table(title=COMMENTS_TABLE_TITLE.format(identifier),
                                                    data_table=construct_csv(
                                                        [comment.to_table() for comment in comments]))

                if domain_data.report_link:
                    siemplify.result.add_entity_link(entity.identifier, domain_data.report_link)

                if create_insight:
                    if not only_suspicious_insight or (only_suspicious_insight and is_risky):
                        if entity.entity_type == EntityTypes.HOSTNAME:
                            siemplify.add_entity_insight(entity, domain_data.to_insight(
                                threshold or f"{percentage_threshold}%"), triggered_by=INTEGRATION_NAME)
                        else:
                            siemplify.create_case_insight(triggered_by=INTEGRATION_NAME,
                                                          title=f"Report: {identifier}",
                                                          content=domain_data.to_insight(threshold or f"{percentage_threshold}%"),
                                                          entity_identifier="",
                                                          severity=InsightSeverity.WARN,
                                                          insight_type=InsightType.General)

                successful_identifiers.append(identifier)
                successful_entities.append(entity)
                siemplify.LOGGER.info("Finished processing entity {0}".format(identifier))

            except Exception as e:
                if isinstance(e, ForceRaiseException):
                    raise
                failed_entities.append(identifier)
                json_results[identifier] = {"execution_status": str(e)}
                siemplify.LOGGER.error("An error occurred on entity {0}".format(identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += "Successfully returned details about the following domains using {}: \n {} \n" \
                .format(PROVIDER_NAME, ', '.join(successful_identifiers))
            siemplify.update_entities(successful_entities)

        if failed_entities:
            output_message += "Action wasn't able to return details about the following domains using {}: \n {} \n"\
                .format(PROVIDER_NAME, ', '.join(failed_entities))

        if not_found_engines:
            output_message += "The following whitelisted engines were not found in {}: \n{} \n"\
                .format(PROVIDER_NAME, ', '.join(not_found_engines))

        if not successful_entities:
            output_message = "No domains were enriched"
            result_value = False

        # Main JSON result
        if json_results:
            result = {
                'results': convert_dict_to_json_result_dict(json_results),
                'is_risky': global_is_risky
            }
            siemplify.result.add_result_json(result)

    except Exception as err:
        output_message = "Error executing action “Get Domain Details”. Reason: {}".format(err)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
