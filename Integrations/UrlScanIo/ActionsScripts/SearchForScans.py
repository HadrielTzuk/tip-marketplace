from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from UrlScanManager import UrlScanManager
from SiemplifyDataModel import EntityTypes
from UtilsManager import get_entity_original_identifier, get_screenshot_content_base64, get_domain_from_entity
from exceptions import SuitableEntitiesNotFoundException
from constants import INTEGRATION_NAME, SEARCH_FOR_SCANS_SCRIPT_NAME, WEB_REPORT_LINK_TITLE, DEFAULT_COUNTS, \
    ATTACHMENT_TITLE, ATTACHMENT_FILE_NAME, CASE_WALL_TABLE_NAME

SUITABLE_ENTITY_TYPES = [EntityTypes.URL, EntityTypes.HOSTNAME, EntityTypes.ADDRESS, EntityTypes.FILEHASH,
                         EntityTypes.FILENAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SEARCH_FOR_SCANS_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Key')
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             input_type=bool, print_value=True)

    max_scans = extract_action_param(siemplify, param_name="Max Scans", input_type=int, default_value=DEFAULT_COUNTS)

    successful_entities, failed_entities, suitable_entities_identifiers = [], [], []
    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    json_results = {}

    suitable_entities_identifiers = list(set([get_domain_from_entity(get_entity_original_identifier(entity))
                                              if entity.entity_type == EntityTypes.URL
                                              else get_entity_original_identifier(entity) for entity in
                                              siemplify.target_entities if entity.entity_type in SUITABLE_ENTITY_TYPES]))
    try:
        manager = UrlScanManager(api_key=api_key, verify_ssl=verify_ssl, force_check_connectivity=True)

        if not suitable_entities_identifiers:
            raise SuitableEntitiesNotFoundException

        for entity in suitable_entities_identifiers:
            try:
                entity_result = manager.search_scans(entity=entity, limit=max_scans)

                if not entity_result:
                    failed_entities.append(entity)
                    siemplify.LOGGER.error("No result for entity {}".format(entity))
                    continue

                json_results[entity] = [result.to_json() for result in entity_result]
                # Add case wall table for entity
                siemplify.result.add_data_table(title=CASE_WALL_TABLE_NAME.format(entity), data_table=construct_csv(
                    [result.to_table() for result in entity_result]))

                for index, details in enumerate(entity_result):
                    # Add report links
                    siemplify.result.add_entity_link(WEB_REPORT_LINK_TITLE.format(INTEGRATION_NAME, entity),
                                                     details.report_link)

                    try:
                        screenshot_content = manager.get_screenshot_content(url=details.screenshot)
                        base64_screenshot = get_screenshot_content_base64(screenshot_content)
                        siemplify.result.add_attachment(title=ATTACHMENT_TITLE.format(index + 1),
                                                        filename=ATTACHMENT_FILE_NAME.format(details.item_id),
                                                        file_contents=base64_screenshot.decode())
                    except Exception as err:
                        siemplify.LOGGER.error('Error getting screenshot content for entity {}'.format(entity))
                        siemplify.LOGGER.exception(err)

                successful_entities.append(entity)

            except Exception as err:
                failed_entities.append(entity)
                siemplify.LOGGER.error("An error occurred on entity {}".format(entity))
                siemplify.LOGGER.exception(err)

        if json_results:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

        if successful_entities:
            output_message += "Successfully listed scans for the following entities:\n {} \n" \
                .format(", ".join(successful_entities))

        if failed_entities:
            output_message += "Action wasn’t able to list scans for the following entities:\n {} \n" \
                .format(", ".join(failed_entities))

        if not successful_entities:
            output_message = "Action wasn’t able to list scans for the available entities."
            result_value = False

    except SuitableEntitiesNotFoundException as err:
        output_message = "No suitable entities were found in the current scope."
        result_value = False
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    except Exception as err:
        output_message = "Error executing action '{}'. Reason: {}".format(SEARCH_FOR_SCANS_SCRIPT_NAME, err)
        status = EXECUTION_STATE_FAILED
        result_value = False
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
