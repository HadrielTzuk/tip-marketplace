from SiemplifyAction import SiemplifyAction
from AzureADManager import AzureADManager
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict, add_prefix_to_dict, unix_now, \
    convert_unixtime_to_datetime
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED,EXECUTION_STATE_TIMEDOUT
from TIPCommon import construct_csv, extract_configuration_param
from constants import ENRICH_HOST_SCRIPT_NAME, INTEGRATION_NAME, ENRICH_TABLE_NAME
from utils import get_entity_original_identifier


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_HOST_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client ID',
                                            is_mandatory=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client Secret',
                                                is_mandatory=True)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Directory ID',
                                         is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""
    successful_entities, failed_entities, json_results = [], [], {}
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.HOSTNAME]

    try:
        manager = AzureADManager(client_id=client_id, client_secret=client_secret, tenant=tenant, verify_ssl=verify_ssl,
                                 force_check_connectivity=True)
           
        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)

            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error(
                    f"Timed out. execution deadline "
                    f"({convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)}) has passed")
                status = EXECUTION_STATE_TIMEDOUT
                break

            siemplify.LOGGER.info(f"Started processing entity: {entity_identifier}")
            try:
                entity_report = manager.get_host(entity_identifier)
                entity.additional_properties.update(entity_report.to_enrichment())
                entity.is_enriched = True
                json_results[entity.identifier] = entity_report.to_json()
                siemplify.result.add_data_table(title=ENRICH_TABLE_NAME.format(entity_identifier),
                                                data_table=construct_csv([entity_report.to_csv()]))
                successful_entities.append(entity)
            except Exception as e:
                failed_entities.append(entity_identifier)
                siemplify.LOGGER.error(f"An error occurred on entity {entity_identifier}")
                siemplify.LOGGER.exception(e)

            siemplify.LOGGER.info(f"Finished processing entity {entity_identifier}")

        if successful_entities:
            entity_identifiers = [get_entity_original_identifier(entity) for entity in successful_entities]
            output_message += f"Successfully enriched hosts: \n{', '.join(entity_identifiers)}\n"
            siemplify.update_entities(successful_entities)
                
            if failed_entities:
                output_message += f"Failed processing entities:\n{', '.join(failed_entities)}\n"
        else:
            output_message = "No entities were enriched."
            result_value = False

        if json_results:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {ENRICH_HOST_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"An error occurred while running action: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
