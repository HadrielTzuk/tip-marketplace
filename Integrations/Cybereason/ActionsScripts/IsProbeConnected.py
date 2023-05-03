from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler, flat_dict_to_csv, \
    convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from CybereasonManager import CybereasonManager, CybereasonManagerNotFoundError
from TIPCommon import extract_configuration_param
from constants import INTEGRATION_NAME, IS_PROBE_CONNECTED_SCRIPT_NAME
from utils import get_entity_original_identifier

SUPPORTED_ENTITY_TYPES = [EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = IS_PROBE_CONNECTED_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = CybereasonManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl,
                                    logger=siemplify.LOGGER, force_check_connectivity=True)

        status = EXECUTION_STATE_COMPLETED
        successful_entities, failed_entities, connection_status = [], [], {}
        result_value = True
        suitable_entities = [entity for entity in siemplify.target_entities if
                             entity.entity_type in SUPPORTED_ENTITY_TYPES]

        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error(f'Timed out. execution deadline '
                                       f'({convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)}) '
                                       f'has passed')
                status = EXECUTION_STATE_TIMEDOUT
                break

            try:
                siemplify.LOGGER.info(f'Started processing entity: {entity_identifier}')
                siemplify.LOGGER.info(f'Fetching machine guid for {entity_identifier}')

                machine_guid = manager.get_machine_guid_by_name_or_fqdn(entity_identifier)

                siemplify.LOGGER.info(f'Found GUID: {machine_guid}')

                siemplify.LOGGER.info(f'Verifying connection status of machine {manager}')
                machine = manager.get_machine(machine_guid)

                if machine.is_connected:
                    siemplify.LOGGER.info(f'Machine {entity_identifier} is connected and active')
                else:
                    siemplify.LOGGER.info(f'Machine {entity_identifier} is not connected')

                connection_status[entity_identifier] = {'is_connected': machine.is_connected}
                successful_entities.append(entity_identifier)
                siemplify.LOGGER.info(f'Finished processing entity {entity_identifier}')

            except Exception as e:
                failed_entities.append(entity_identifier)
                siemplify.LOGGER.error(f'An error occurred on entity {entity_identifier}')
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message = f'Successfully retrieved information about connectivity for the following entities:  ' \
                             f'{", ".join(successful_entities)}\n'
            if failed_entities:
                output_message += f'Action wasn\'t able to retrieve information about connectivity for the following ' \
                                  f'entities: {", ".join(failed_entities)}\n'
        else:
            output_message = "No information about connectivity was retrieved for the provided entities."
            result_value = False

        if connection_status:
            siemplify.result.add_data_table("Connection Status", connection_status)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(connection_status))

    except Exception as e:
        output_message = f'Error executing action "{IS_PROBE_CONNECTED_SCRIPT_NAME}". Reason: {e}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
