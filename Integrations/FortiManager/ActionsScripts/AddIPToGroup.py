from SiemplifyUtils import output_handler, unix_now
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from FortiManager import FortiManager, WorkflowError
from ScriptResult import (
    EXECUTION_STATE_COMPLETED,
    EXECUTION_STATE_FAILED,
    EXECUTION_STATE_INPROGRESS
)
from FortiUtils import is_async_action_global_timeout_approaching


PROVIDER = 'FortiManager'
ACTION_NAME = 'FortiManager_AddIPToGroup'


@output_handler
def main():
    action_start_time = unix_now()
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    verify_ssl = conf.get('Verify SSL', 'false').lower() == 'true'
    workflow_mode = conf.get('Workflow Mode', 'false').lower() == 'true'

    forti_manager = FortiManager(conf['API Root'], conf['Username'], conf['Password'], verify_ssl, siemplify=siemplify,
                                 workflow_mode=workflow_mode)

    result_value = False
    execution_state = EXECUTION_STATE_COMPLETED
    errors = []
    success_entities = []

    target_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS]

    # Parameters.
    adom_name = siemplify.parameters.get('ADOM Name', 'root')
    address_group_name = siemplify.parameters.get('Address Group Name')

    try:
        forti_manager.check_session(adom_name)

        for entity in target_entities:
            try:
                # Construct firewall address object name.
                address_object_name = forti_manager.construct_address_object_name(entity.identifier)
                if not forti_manager.is_address_object_exist(adom_name, address_object_name):
                    # Create address object.
                    address_object_name = forti_manager.create_address_object(adom_name, entity.identifier)
                # Add address object to an address group.
                forti_manager.add_address_object_to_address_group(adom_name, address_group_name, address_object_name)

                success_entities.append(entity)
                result_value = True

            except WorkflowError:
                forti_manager.finish_session(adom_name)
                raise

            except Exception as err:
                error_message = 'Error accrued with {0}, Error: {1}'.format(entity.identifier, err.message)
                siemplify.LOGGER.error(error_message)
                siemplify.LOGGER.exception(err)
                errors.append(error_message)

        if success_entities:
            output_message = 'The following entities were added to group: {0}'.format(', '.join(
                [entity.identifier for entity in success_entities]))
        else:
            output_message = 'No entities were added to group.'

        if errors:
            output_message = "{0} \n \n Errors:  \n {1}".format(output_message, ' \n '.join(errors))

        forti_manager.finish_session(adom_name)

    except WorkflowError as err:
        output_message_pattern = 'Error executing action "{0}". Reason: {1}.'
        output_message = output_message_pattern.format(ACTION_NAME, err.message)

        if err.code != -20055:
            execution_state = EXECUTION_STATE_FAILED
        elif is_async_action_global_timeout_approaching(siemplify, action_start_time):
            execution_state = EXECUTION_STATE_FAILED
            output_message = output_message_pattern.format(
                ACTION_NAME,
                'action ran into a timeout, while waiting for the adom to be unlocked. '
                'Please increase the timeout in IDE and try again.'
            )
        else:
            execution_state = EXECUTION_STATE_INPROGRESS
            output_message = "Waiting for the the adom to be unlocked..."

        siemplify.LOGGER.error(err.message)
        siemplify.LOGGER.exception(err)

    finally:
        forti_manager.logout()

    siemplify.end(output_message, result_value, execution_state)


if __name__ == "__main__":
    main()
