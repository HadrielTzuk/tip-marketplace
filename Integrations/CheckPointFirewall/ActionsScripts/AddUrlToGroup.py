from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from CheckpointManager import CheckpointManager
from TIPCommon import extract_configuration_param, extract_action_param
from constants import ADD_URL_TO_GROUP_SCRIPT_NAME, INTEGRATION_NAME, PARAMETERS_NEW_LINE_DELIMITER
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from exceptions import InvalidGroupException

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_URL_TO_GROUP_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    # INIT INTEGRATION CONFIGURATION:
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Server Address",
                                                 is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    domain_name = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Domain",
                                              is_mandatory=False, default_value="")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)
    policy_name = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Policy Name",
                                              is_mandatory=True)
    group_name = extract_action_param(siemplify, param_name='URLs Group Name', print_value=True, is_mandatory=True)

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    successful_entities, failed_entities = [], []
    relevant_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.URL]

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    try:
        manager = CheckpointManager(server_address=server_address, username=username, password=password,
                                    domain=domain_name, verify_ssl=verify_ssl)

        for entity in relevant_entities:
            try:
                siemplify.LOGGER.info('\n\nStart process for the following entity: {}'.format(entity.identifier))
                manager.block_url_in_group(entity.identifier, entity.identifier.lower(), group_name)
                successful_entities.append(entity.identifier)
                siemplify.LOGGER.info('Successfully processed the following entity: {}'.format(entity.identifier))
            except InvalidGroupException:
                raise
            except Exception as err:
                failed_entities.append(entity.identifier)
                siemplify.LOGGER.error('Action was not able to process the following entity: {}'.format(entity.identifier))
                siemplify.LOGGER.exception(err)

            siemplify.LOGGER.info('End process for the following entity: {}'.format(entity.identifier))

        if successful_entities:
            output_message += 'Successfully added the following URLs to the {} Checkpoint FireWall Group: {}\n'\
                .format(group_name, PARAMETERS_NEW_LINE_DELIMITER.join(successful_entities))

        if failed_entities:
            output_message += "Action wasn’t able to add the following URLs to the {} Checkpoint FireWall Group: " \
                             "{}\n".format(group_name, PARAMETERS_NEW_LINE_DELIMITER.join(failed_entities))

        if not successful_entities:
            output_message = "No URLs were added to the {} Checkpoint FireWall Group.".format(group_name)
            result_value = False

        # All the changes done will be effective only after install is called.
        manager.install_policy(policy_name)
        manager.log_out()
    except Exception as err:
        output_message = 'No URLs were added to the {} Checkpoint FireWall Group. Reason: {}'.format(group_name, err)
        result_value = False
        # For invalid groups playbook should not stop
        if not isinstance(err, InvalidGroupException):
            status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
