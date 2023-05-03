from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv, add_prefix_to_dict
from VirusTotalManager import VirusTotalManager
from constants import PROVIDER_NAME, INTEGRATION_NAME, ENRICH_IP_SCRIPT_NAME, DEFAULT_COMMENTS_COUNT, \
    DATA_ENRICHMENT_PREFIX, COMMENTS_TABLE_TITLE, REPORT_LINK_TITLE, WIDGET_THEME_MAPPING
from exceptions import ForceRaiseException
from UtilsManager import get_entity_original_identifier


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_IP_SCRIPT_NAME

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
    create_insight = extract_action_param(siemplify, param_name="Create Insight", is_mandatory=False,
                                          input_type=bool, default_value=True)
    only_suspicious_insight = extract_action_param(siemplify, param_name="Only Suspicious Entity Insight",
                                                   is_mandatory=False, input_type=bool, default_value=False)
    max_returned_comments = extract_action_param(siemplify, param_name="Max Comments To Return", is_mandatory=False,
                                                 input_type=int, default_value=10)
    widget_theme = extract_action_param(siemplify, param_name="Widget Theme", print_value=True)
    fetch_widget = extract_action_param(siemplify, param_name="Fetch Widget", input_type=bool, default_value=True,
                                        print_value=True)
    whitelists = [item.strip() for item in whitelist_str.split(',') if item] if whitelist_str else []

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    failed_entities = []
    not_found_engines = set()
    json_results = {}
    global_is_risky = False
    comments = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS]

    try:
        if not threshold and not percentage_threshold:
            raise Exception(f"either \"Engine Threshold\" or \"Engine Percentage Threshold\" should be provided.")

        if percentage_threshold and (percentage_threshold > 100 or percentage_threshold < 0):
            raise Exception(f"value for the parameter \"Engine Percentage Threshold\" is invalid. Please check it. "
                  f"The value should be in range from 0 to 100")

        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)

        for entity in suitable_entities:
            is_risky = False

            siemplify.LOGGER.info("Started processing entity: {}".format(get_entity_original_identifier(entity)))

            try:
                ip_data = manager.get_ip_data(ip=get_entity_original_identifier(entity), show_entity_status=True)
                ip_data.set_supported_engines(whitelists)
                not_found_engines.update(set(ip_data.invalid_engines))
                if retrieve_comments:
                    comments = manager.get_comments(url_type='ip_addresses', entity=get_entity_original_identifier(entity),
                                                    limit=max_returned_comments, show_entity_status=True)

                widget_link, widget_html = manager.get_widget(
                    get_entity_original_identifier(entity), show_entity_status=True,
                    theme_colors=WIDGET_THEME_MAPPING.get(widget_theme)
                ) if fetch_widget else (None, None)

                ip_data.widget_link = widget_link
                ip_data.widget_html = widget_html

                if threshold:
                    if ip_data.threshold >= int(threshold):
                        is_risky = True
                        global_is_risky = True
                        entity.is_suspicious = True
                else:
                    if int(ip_data.percentage_threshold) >= percentage_threshold:
                        is_risky = True
                        global_is_risky = True
                        entity.is_suspicious = True

                # Enrich entity
                entity.additional_properties.update(ip_data.to_enrichment_data())
                # Add case wall table for entity
                siemplify.result.add_data_table(title="{}".format(entity.identifier),
                                                data_table=construct_csv(ip_data.to_table()))
                # Fill json with every entity data
                json_results[get_entity_original_identifier(entity)] = ip_data.to_json(comments=comments,
                                                                                       widget_link=widget_link)
                json_results[get_entity_original_identifier(entity)].update({"execution_status": "success"})
                # Create case wall table for comments
                if comments:
                    siemplify.result.add_data_table(title=COMMENTS_TABLE_TITLE.format(get_entity_original_identifier(entity)),
                                                    data_table=construct_csv([comment.to_table() for comment in comments]))

                if ip_data.report_link:
                    siemplify.result.add_entity_link(entity.identifier, ip_data.report_link)

                if create_insight:
                    if not only_suspicious_insight or (only_suspicious_insight and is_risky):
                        siemplify.add_entity_insight(entity, ip_data.to_insight(threshold or f"{percentage_threshold}%"),
                                                     triggered_by=INTEGRATION_NAME)

                entity.is_enriched = True
                successful_entities.append(entity)
                siemplify.LOGGER.info("Finished processing entity {0}".format(get_entity_original_identifier(entity)))

            except Exception as e:
                if isinstance(e, ForceRaiseException):
                    raise
                failed_entities.append(get_entity_original_identifier(entity))
                json_results[get_entity_original_identifier(entity)] = {"execution_status": str(e)}
                siemplify.LOGGER.error("An error occurred on entity {0}".format(get_entity_original_identifier(entity)))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += "Successfully enriched the following IPs using {}: \n {} \n" \
                .format(PROVIDER_NAME, ', '.join([get_entity_original_identifier(entity) for entity in successful_entities]))
            siemplify.update_entities(successful_entities)

        if failed_entities:
            output_message += "Action wasn't able to enrich the following IPs using {}: \n {} \n"\
                .format(PROVIDER_NAME, ', '.join(failed_entities))

        if not_found_engines:
            output_message += "The following whitelisted engines were not found in {}: \n{} \n" \
                .format(PROVIDER_NAME, ', '.join(list(not_found_engines)))

        if not successful_entities:
            output_message = "No IPs were enriched"
            result_value = False

        # Main JSON result
        if json_results:
            siemplify.result.add_result_json({
                'results': convert_dict_to_json_result_dict(json_results),
                'is_risky': global_is_risky
            })
    except Exception as err:
        output_message = "Error executing action “Enrich IP”. Reason: {}".format(err)
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
