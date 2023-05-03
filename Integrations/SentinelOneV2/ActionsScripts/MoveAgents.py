from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from exceptions import SentinelOneV2NotFoundError, SentinelOneV2PermissionError, SentinelOneV2ValidationError
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler
from constants import INTEGRATION_NAME, PRODUCT_NAME, MOVE_AGENTS_SCRIPT_NAME
from utils import get_entity_original_identifier
from SentinelOneV2Factory import SentinelOneV2ManagerFactory


SUPPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = MOVE_AGENTS_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    group_id = extract_action_param(siemplify, param_name='Group ID', print_value=True)
    group_name = extract_action_param(siemplify, param_name='Group Name', print_value=True)

    group_identifier_type, group_identifier = ('ID', group_id) if group_id else ('Name', group_name)

    found_agents, success_entities, ignored_entities, failed_entities = [], [], [], set()
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]
    request_group_id = group_id
    output_message = ''

    try:
        if not (group_id or group_name):
            raise SentinelOneV2ValidationError("either 'Group Name' or 'Group ID' should be provided.")

        manager = SentinelOneV2ManagerFactory().get_manager(api_root=api_root, api_token=api_token,
                                                            verify_ssl=verify_ssl,
                                                            force_check_connectivity=True)
        if not request_group_id:
            group = manager.get_group_or_raise(group_name)
            request_group_id = group.id

        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)
            try:
                siemplify.LOGGER.info("Processing entity {}".format(entity_identifier))
                found_agent = None

                if entity.entity_type == EntityTypes.HOSTNAME:
                    try:
                        siemplify.LOGGER.info('Fetching agent for hostname {}'.format(entity_identifier))
                        found_agent = manager.get_agent_by_hostname(entity_identifier)
                    except SentinelOneV2NotFoundError as e:
                        siemplify.LOGGER.info(e)
                        siemplify.LOGGER.info('Skipping entity {}'.format(entity_identifier))

                elif entity.entity_type == EntityTypes.ADDRESS:
                    try:
                        siemplify.LOGGER.info('Fetching agent for address {}'.format(entity_identifier))
                        found_agent = manager.get_agent_by_ip(entity_identifier)
                    except SentinelOneV2NotFoundError as e:
                        siemplify.LOGGER.info(e)
                        siemplify.LOGGER.info('Skipping entity {}'.format(entity_identifier))

                if found_agent:
                    found_agents.append((found_agent, entity_identifier))
                    siemplify.LOGGER.info('Found agent {} for entity {}'.format(found_agent.id, entity_identifier))
                else:
                    failed_entities.add(entity_identifier)
            except Exception as e:
                failed_entities.add(entity_identifier)
                siemplify.LOGGER.error('An error occurred on entity {0}'.format(entity_identifier))
                siemplify.LOGGER.exception(e)

        if found_agents:
            siemplify.LOGGER.info('Moving {} agents to group {}.'.format(len(found_agents), group_identifier))
            for agent, entity_identifier in found_agents:
                try:
                    moved_agents_count = manager.move_agents(agent_ids=[agent.id], group_id=request_group_id)
                    (success_entities if moved_agents_count > 0 else ignored_entities).append(entity_identifier)
                except Exception as e:
                    siemplify.LOGGER.exception(e)
                    siemplify.LOGGER.error('Unable to move agent {} to group {}'.format(agent.id, group_identifier))
                    if isinstance(e, SentinelOneV2NotFoundError):
                        raise
                    failed_entities.add(entity_identifier)

        if success_entities:
            output_message += 'Successfully moved the following endpoints to the group with {} {} in {}:\n{}\n' \
                .format(group_identifier_type, group_identifier, PRODUCT_NAME, ', '.join(success_entities))

        if failed_entities:
            output_message += "Action wasn't able to move the following endpoints to the group with {} {} in {}:\n{}\n"\
                              .format(group_identifier_type, group_identifier, PRODUCT_NAME, ', '.join(failed_entities))
        if ignored_entities:
            output_message += 'The following endpoints are already a part of the group with {} {} in {}:\n{}\n'\
                .format(group_identifier_type, group_identifier, PRODUCT_NAME, ', '.join(ignored_entities))

        elif not success_entities:
            result_value = False
            output_message = 'No endpoints were moved to the group {} {} in {}' \
                .format(group_identifier_type, group_identifier, PRODUCT_NAME)

    except Exception as e:
        output_message = "Action wasn't able to move endpoints to the group with {} {} in {}. Reason: Group was not " \
                         "found.".format(group_identifier_type, group_identifier, PRODUCT_NAME) \
            if isinstance(e, SentinelOneV2NotFoundError)\
            else "Error executing action '{}'. Reason: {}".format(MOVE_AGENTS_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
