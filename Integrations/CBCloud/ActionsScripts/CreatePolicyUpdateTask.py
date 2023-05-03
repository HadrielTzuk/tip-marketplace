from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from CBCloudManager import CBCloudManager, CBCloudUnauthorizedError
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, CREATE_POLICY_UPDATE_TASK_SCRIPT_NAME, NEW_LINE, PROVIDER_NAME
from utils import get_entity_original_identifier

ENTITIES_MAPPER = {
    EntityTypes.ADDRESS: 'query',
    EntityTypes.HOSTNAME: 'starts_with_name'
}
DEFAULT_LIMIT = 3


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_POLICY_UPDATE_TASK_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    org_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Organization Key',
                                          is_mandatory=True)
    api_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API ID',
                                         is_mandatory=True)
    api_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name='API Secret Key', is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    policy_id = extract_action_param(siemplify, param_name='Policy ID', is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    result_value = True
    successful_entities, multimatch_entities, missing_entities, failed_entities = [], [], [], []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in ENTITIES_MAPPER.keys()]

    try:
        manager = CBCloudManager(api_root=api_root, org_key=org_key, api_id=api_id, api_secret_key=api_secret_key,
                                 verify_ssl=verify_ssl, force_check_connectivity=True)

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
                siemplify.LOGGER.info(f"Fetching device info for entity {entity_identifier}")

                params = {
                    ENTITIES_MAPPER[entity.entity_type]: entity_identifier,
                    'limit': DEFAULT_LIMIT
                }
                devices = manager.search_devices(**params)

                if not devices:
                    # Device was not found in CB Cloud - skip entity
                    missing_entities.append(entity_identifier)
                    siemplify.LOGGER.info(f"No devices found for entity {entity_identifier}. Skipping.")
                    continue

                if len(devices) > 1:
                    multimatch_entities.append(entity_identifier)
                    siemplify.LOGGER.info(
                        f"Multiple matches found for entity {entity_identifier}, taking first match for enrichment.")

                # Take the first matching device
                device = devices[-1]

                siemplify.LOGGER.info(
                    f"Creating policy update task for device: {device.id}, entity:{entity_identifier}.")
                manager.create_policy_update_task(policy_id=policy_id, device_id=device.id)

                successful_entities.append(entity_identifier)
                siemplify.LOGGER.info(f"Finished processing entity {entity_identifier}")

            except Exception as e:
                failed_entities.append(entity_identifier)
                siemplify.LOGGER.error(f"An error occurred on entity {entity_identifier}")
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += f"Successfully changed device policy to {policy_id} for the following entities:\n " \
                              f"{NEW_LINE.join(successful_entities)} \n"
        else:
            output_message += "No tasks were created. \n"
            result_value = False

        if multimatch_entities:
            output_message += f"Multiple matches were found in {PROVIDER_NAME}, taking first match for the following " \
                              f"entities:\n {NEW_LINE.join(multimatch_entities)} \n"

        if missing_entities:
            output_message += f"Action was not able to find matching {PROVIDER_NAME} devices for the following " \
                              f"entities:\n {NEW_LINE.join(missing_entities)} \n"
        if failed_entities:
            output_message += f"Action was not able assign policy {policy_id} for {PROVIDER_NAME} devices for the " \
                              f"following entities:\n {NEW_LINE.join(failed_entities)}"
    except Exception as e:
        output_message = f"Error executing action {CREATE_POLICY_UPDATE_TASK_SCRIPT_NAME}. Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f'\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
