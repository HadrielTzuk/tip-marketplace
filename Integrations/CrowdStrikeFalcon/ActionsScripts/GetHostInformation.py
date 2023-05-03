from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from CrowdStrikeManager import CrowdStrikeManager
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import convert_dict_to_json_result_dict
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param, add_prefix_to_dict, dict_to_flat
from constants import API_ROOT_DEFAULT, INTEGRATION_NAME, GET_HOST_INFORMATION_SCRIPT_NAME, DEFAULT_DEVICE_VENDOR, \
    PRODUCT_NAME
from utils import get_entity_original_identifier

ENTITIES_MAPPER = {
    EntityTypes.ADDRESS: 'local_ip',
    EntityTypes.HOSTNAME: 'starts_with_name'
}
EXCLUDE_KEYS_DEFAULT = ['policies', 'device_policies']


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_HOST_INFORMATION_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           default_value=API_ROOT_DEFAULT)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client API ID')
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name='Client API Secret')
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                          input_type=bool, is_mandatory=True)

    create_insight = extract_action_param(siemplify, param_name='Create Insight', default_value=True, print_value=True,
                                          input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    successful_entities, failed_entities, json_results = [], [], {}
    login_histories, online_states = {}, {}
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in ENTITIES_MAPPER.keys()]

    try:
        manager = CrowdStrikeManager(client_id=client_id, client_secret=client_secret, use_ssl=use_ssl,
                                     api_root=api_root)
        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)
            params = {
                ENTITIES_MAPPER[entity.entity_type]: entity_identifier
            }
            devices = manager.search_devices(**params)
            if not devices:
                failed_entities.append(entity_identifier)
                continue

            try:
                login_histories = {item.device_id: item.recent_logins for item in
                                   manager.get_devices_login_histories([device.device_id for device in devices])}
            except Exception:
                siemplify.LOGGER.error(f"An error occurred on getting login history for entity {entity.identifier}")

            try:
                online_states = {item.device_id: item.state for item in
                                 manager.get_devices_online_states([device.device_id for device in devices])}
            except Exception:
                siemplify.LOGGER.error(f"An error occurred on getting online state for entity {entity.identifier}")

            for index, device in enumerate(devices):
                device_data = device.to_enrichment_data(
                    exclude_keys=EXCLUDE_KEYS_DEFAULT,
                    additional_prefix=index if len(devices) != 1 else None
                )
                entity.additional_properties.update(device_data)

                if create_insight:
                    siemplify.add_entity_insight(entity, device.to_insight(entity_type=entity.entity_type))

            entity.is_enriched = True
            successful_entities.append(entity)

            json_results[entity_identifier] = [
                {
                    **device.to_json(),
                    "recent_logins": login_histories.get(device.device_id, []),
                    "online_status": online_states.get(device.device_id, "")
                } for device in devices
            ]

        if successful_entities:
            output_message = f'Successfully enriched the following entities using {PRODUCT_NAME}: ' \
                             f'{", ".join([get_entity_original_identifier(entity) for entity in successful_entities])}\n'
            siemplify.update_entities(successful_entities)

            if failed_entities:
                output_message += f'Action wasn\'t able to enrich the following entities using {PRODUCT_NAME}: ' \
                                  f'{", ".join(failed_entities)}\n'
        else:
            result_value = False
            output_message = 'No entities were enriched.'

        if json_results:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    except Exception as e:
        output_message = f"Error executing action '{GET_HOST_INFORMATION_SCRIPT_NAME}'. Reason: {e}"
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
