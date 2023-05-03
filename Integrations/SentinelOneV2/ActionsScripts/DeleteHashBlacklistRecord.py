from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyDataModel import EntityTypes
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import DEFAULT_GET_BLACKLIST_ITEM_LIMIT, REMOVE_HASH_BLACKLIST_RECORD_SCRIPT_NAME, INTEGRATION_NAME, PRODUCT_NAME, SHA1_LENGTH
from exceptions import SentinelOneV2ValidationError, SentinelOneV2AlreadyExistsError, SentinelOneV2PermissionError
from utils import get_entity_original_identifier
from SentinelOneV2Factory import SentinelOneV2ManagerFactory
from utils import string_to_multi_value

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = REMOVE_HASH_BLACKLIST_RECORD_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)
    
    site_ids = string_to_multi_value(extract_action_param(siemplify, param_name='Site IDs', print_value=True))
    group_ids = string_to_multi_value(extract_action_param(siemplify, param_name='Group IDs', print_value=True))
    account_ids = string_to_multi_value(extract_action_param(siemplify, param_name='Account IDs', print_value=True))
    remove_from_global_list = extract_action_param(siemplify, param_name='Remove from global black list',
                                                   input_type=bool, print_value=True)
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.FILEHASH]

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ''
    successful_entities, failed_entities, not_found_entities = [], [], []

    try:
        if not site_ids and not group_ids and not account_ids and not remove_from_global_list:
            raise SentinelOneV2ValidationError(
                "at least one value should be provided for \"Site IDs\" or \"Group IDs\" or \"Account IDs\" parameters "
                "or \"Remove from global black list\" should be enabled."
            )

        manager = SentinelOneV2ManagerFactory().get_manager(api_root=api_root, api_token=api_token,
                                                            verify_ssl=verify_ssl, force_check_connectivity=True)

        for entity in suitable_entities:
            entity_original_identifier = get_entity_original_identifier(entity)
            siemplify.LOGGER.info("Started processing entity: {}".format(entity_original_identifier))            
            if len(entity.identifier) == SHA1_LENGTH:
                result = manager.get_blacklist_items(hash_value=entity_original_identifier, site_ids=site_ids,
                                                     group_ids=group_ids, account_ids=account_ids,
                                                     limit=DEFAULT_GET_BLACKLIST_ITEM_LIMIT, query=None,
                                                     tenant=remove_from_global_list)
                
                if result:
                    hash_object_id = result[0].hash_id
                    try:
                        _results = manager.delete_hash_black_list_record(hash_object_id=hash_object_id)
                        successful_entities.append(entity_original_identifier)

                    except Exception as err:
                        siemplify.LOGGER.error("An error occurred on entity: {}: {}".format(entity_original_identifier, err))
                        siemplify.LOGGER.exception(err)
                        failed_entities.append(entity_original_identifier)
                        if isinstance(err, SentinelOneV2PermissionError):
                            raise                
                else:
                    siemplify.LOGGER.info("Entity: {} was not found in {}.".format(entity_original_identifier, PRODUCT_NAME))  
                    not_found_entities.append(entity_original_identifier)
                        
            else:
                siemplify.LOGGER.info("Entity: {} is not a SHA1 Hash.".format(entity_original_identifier))
                failed_entities.append(entity_original_identifier)

            siemplify.LOGGER.info("Finished processing entity: {}".format(entity_original_identifier))

        if successful_entities:
            output_message = 'Successfully removed the following hashes from blacklist in {}: \n {}\n'\
                .format(PRODUCT_NAME, '\n'.join(successful_entities))

        if not_found_entities:
            output_message += "The following hashes were not found in the blacklist in {}: \n{}\n"\
                .format(PRODUCT_NAME, "\n".join(not_found_entities))

        if failed_entities:
            output_message += "Action wasn't able to remove the following hashes from blacklist in {}: \n{}\n"\
                .format(PRODUCT_NAME, '\n'.join(failed_entities))

        if not successful_entities :
            output_message = 'No hashes were removed from blacklist in {}.'.format(PRODUCT_NAME)
            result_value = False

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(REMOVE_HASH_BLACKLIST_RECORD_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
