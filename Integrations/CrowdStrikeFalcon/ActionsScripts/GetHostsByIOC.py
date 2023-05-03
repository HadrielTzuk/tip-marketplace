from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import get_domain_from_entity, convert_dict_to_json_result_dict, construct_csv
from CrowdStrikeManager import CrowdStrikeManager
from TIPCommon import extract_configuration_param
from constants import API_ROOT_DEFAULT, GET_HOSTS_BY_IOC_SCRIPT_NAME, INTEGRATION_NAME, PRODUCT_NAME, HOSTS_BY_IOC, \
    TYPES_IOC_MAPPER, SUPPORTED_HASH_TYPES
from utils import get_hash_type, get_domain_from_entity, get_entity_original_identifier
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_HOSTS_BY_IOC_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           default_value=API_ROOT_DEFAULT)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client API ID')
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name='Client API Secret')
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                          input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    output_message = ""
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    json_results = {}

    try:
        manager = CrowdStrikeManager(client_id=client_id, client_secret=client_secret, use_ssl=use_ssl,
                                     api_root=api_root)
        suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type
                             in TYPES_IOC_MAPPER.keys()]

        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)
            entity_type = TYPES_IOC_MAPPER[entity.entity_type]

            ioc_value = entity_identifier if entity.entity_type != EntityTypes.URL \
                else get_domain_from_entity(entity_identifier)
            try:
                ioc_type = entity_type if entity_type else get_entity_hash_type(entity_identifier)
            except Exception as e:
                siemplify.LOGGER.exception(e)
                siemplify.LOGGER.error(f'Invalid hash type. Skip on entity: {entity_identifier}.')
                continue

            try:
                if not ioc_type or not ioc_value:
                    raise

                devices = manager.get_devices_ran_on(ioc_type=ioc_type, value=ioc_value)
                if devices:
                    json_results[entity_identifier] = [device.to_json() for device in devices]
                    siemplify.result.add_entity_table(HOSTS_BY_IOC.format(entity_identifier),
                                                      construct_csv([device.to_csv() for device in devices]))

            except Exception as e:
                siemplify.LOGGER.error(f"An error occurred on entity: {entity_identifier}. {e}.")
                siemplify.LOGGER.exception(e)

        if json_results:
            output_message = f"Successfully retrieved hosts related to the provided IOCs in {PRODUCT_NAME}."
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
        else:
            output_message = f"No hosts were related to the provided IOCs in {PRODUCT_NAME}."
            result_value = False

    except Exception as e:
        output_message = f"Error executing action '{GET_HOSTS_BY_IOC_SCRIPT_NAME}'. Reason: {e}"
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


def get_entity_hash_type(entity_identifier):
    hash_type = get_hash_type(entity_identifier)
    if hash_type not in SUPPORTED_HASH_TYPES:
        raise

    return hash_type

if __name__ == '__main__':
    main()
