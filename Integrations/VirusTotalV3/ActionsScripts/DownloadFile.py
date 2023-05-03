from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from VirusTotalManager import VirusTotalManager
from constants import PROVIDER_NAME, DOWNLOAD_FILE_SCRIPT_NAME, INTEGRATION_NAME, SHA256_LENGTH, SHA1_LENGTH, MD5_LENGTH
import os 
from UtilsManager import save_attachment, get_entity_original_identifier
from exceptions import VirusTotalNotFoundException

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = DOWNLOAD_FILE_SCRIPT_NAME

    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool)
    # Parameters
    download_folder_path = extract_action_param(siemplify, param_name="Download Folder Path", is_mandatory=True, print_value=True)
    overwrite = extract_action_param(siemplify, param_name="Overwrite", is_mandatory=False,default_value=True,
                                             input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    successful_entities = []
    failed_entities = []
    json_results = {}
    absolute_file_paths = []

    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.FILEHASH]
    try:
        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)

        for entity in suitable_entities:
            siemplify.LOGGER.info("Started processing entity: {}".format(get_entity_original_identifier(entity)))

            if len(get_entity_original_identifier(entity)) not in [MD5_LENGTH, SHA1_LENGTH, SHA256_LENGTH]:
                siemplify.LOGGER.error("Hash type of hash: {} is not supported. Provide either MD5, SHA-256 or SHA-1.".format(get_entity_original_identifier(entity)))
                continue

            try:
                absolute_file_path = "{}{}".format(download_folder_path, get_entity_original_identifier(entity))
                if not overwrite:
                    if os.path.exists(absolute_file_path):
                        raise Exception(f'files with path {absolute_file_path} already exist. Please delete the files or set "Overwrite" to true.')
                
                file_content = manager.get_file(entity_hash=get_entity_original_identifier(entity))
                
                save_attachment(path=download_folder_path, name=get_entity_original_identifier(entity), content=file_content)
                absolute_file_paths.append(absolute_file_path)
                
                successful_entities.append(entity)

            except VirusTotalNotFoundException as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error("An error occurred on entity {}. Reason: Not found in {}.".format(get_entity_original_identifier(entity), PROVIDER_NAME))
                siemplify.LOGGER.exception(e)
                continue
            
            except Exception as e:
                raise

            siemplify.LOGGER.info("Finished processing entity {}".format(get_entity_original_identifier(entity)))

        if successful_entities:
            json_result = {
                "absolute_file_paths": absolute_file_paths
            }
            output_message += "Successfully returned related files for the following entities in {}: {}" \
                .format(PROVIDER_NAME, ', '.join([entity.identifier for entity in successful_entities]))
            siemplify.result.add_result_json(json_result)

        if failed_entities:
            output_message += "\n No related files were found for the following entities in {}: \n {} \n"\
                .format(PROVIDER_NAME, ', '.join([entity.identifier for entity in failed_entities]))

        if not successful_entities:
            output_message = "No related files were found for the provided entities in {}.".format(PROVIDER_NAME)
            result_value = False

    except Exception as err:
        output_message = "Error executing action {}. Reason: {}".format(DOWNLOAD_FILE_SCRIPT_NAME, err)
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
