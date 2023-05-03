from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler,\
     convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from LogRhythmManager import LogRhythmRESTManager
from TIPCommon import extract_configuration_param, extract_action_param, add_prefix_to_dict, flat_dict_to_csv
from constants import INTEGRATION_NAME, ENRICH_ENTITIES_SCRIPT_NAME
from utils import get_entity_original_identifier

SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_ENTITIES_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                          is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    create_insight = extract_action_param(siemplify, param_name="Create Insight", default_value=True,
                                           print_value=True, input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    successful_entities, failed_entities, csv_output, json_results = [], [], [], {}
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITIES]

    try:
        manager = LogRhythmRESTManager(api_root=api_root, api_key=api_key, verify_ssl=verify_ssl,
                                       force_check_connectivity=True)

        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)

            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error(f"Timed out. execution deadline "
                                       f"({convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)}) "
                                       f"has passed")
                status = EXECUTION_STATE_TIMEDOUT
                break

            try:
                siemplify.LOGGER.info(f"Started processing entity: {entity_identifier}")
                entity_details = manager.get_entity_details(entity_identifier=entity_identifier)
                if not entity_details:
                    failed_entities.append(entity_identifier)
                    continue
                json_results[entity_identifier] = entity_details.as_json()
                enrichment_table = entity_details.as_enrichment_data()
                csv_output = entity_details.as_table_data()
                entity.additional_properties.update(
                    add_prefix_to_dict(enrichment_table, INTEGRATION_NAME)
                )
                entity.is_enriched = True
                successful_entities.append(entity)
                if csv_output:
                    siemplify.result.add_data_table(entity_identifier, flat_dict_to_csv(csv_output))
                if create_insight:
                    siemplify.add_entity_insight(entity, entity_details.to_insight())
                siemplify.LOGGER.info(f"Finished processing entity {entity_identifier}")
            except Exception as e:
                failed_entities.append(entity_identifier)
                siemplify.LOGGER.error(f"An error occurred on entity {entity_identifier}")
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message = f"Successfully enriched the following entities using information from {INTEGRATION_NAME}:\n " \
                             f"{', '.join([get_entity_original_identifier(entity) for entity in successful_entities])}\n"
            siemplify.update_entities(successful_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

            if failed_entities:
                output_message += f"Action wasn't able to enrich the following entities using information from " \
                                  f"{INTEGRATION_NAME}: \n {', '.join(failed_entities)} \n"
        else:
            output_message = "None of the provided entities were enriched. \n"
            result_value = False

    except Exception as e:
        output_message = f"Error executing action {ENRICH_ENTITIES_SCRIPT_NAME}. Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f'\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
