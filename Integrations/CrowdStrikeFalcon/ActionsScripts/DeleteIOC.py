from CrowdStrikeManager import CrowdStrikeManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param
from constants import API_ROOT_DEFAULT, DELETE_IOC_SCRIPT_NAME, INTEGRATION_NAME, PRODUCT_NAME, TYPES_IOC_MAPPER
from utils import get_domain_from_entity, get_entity_original_identifier


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = DELETE_IOC_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           default_value=API_ROOT_DEFAULT)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client API ID')
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name='Client API Secret')
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                          input_type=bool, is_mandatory=True)

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    successful_entities, failed_entities = [], []

    try:
        manager = CrowdStrikeManager(client_id=client_id, client_secret=client_secret, use_ssl=use_ssl,
                                     api_root=api_root)
        suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type
                             in TYPES_IOC_MAPPER.keys()]

        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)

            ioc_value = entity_identifier if entity.entity_type != EntityTypes.URL \
                else get_domain_from_entity(entity_identifier)

            try:
                if not ioc_value:
                    raise

                id_list = manager.get_ioc_id(ioc_value=ioc_value)
                
                if not id_list:
                    raise Exception(f"Failed to get ID for {ioc_value} IOC")
                
                manager.delete_ioc(ioc_id=id_list[0])
                successful_entities.append(entity_identifier)

            except Exception as e:
                failed_entities.append(entity_identifier)
                siemplify.LOGGER.error(f"An error occurred on entity: {entity_identifier}.")
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message = f"Successfully deleted the following custom IOCs in {PRODUCT_NAME}: " \
                             f"{', '.join(successful_entities)}\n"
            if failed_entities:
                output_message += f"The following custom IOCs were not a part of {PRODUCT_NAME} instance: " \
                                  f"{', '.join(failed_entities)}"
        else:
            output_message = f"All of the provided IOCs were not a part of {PRODUCT_NAME} instance."

    except Exception as e:
        output_message = f"Error executing action '{DELETE_IOC_SCRIPT_NAME}'. Reason: {e}"
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
