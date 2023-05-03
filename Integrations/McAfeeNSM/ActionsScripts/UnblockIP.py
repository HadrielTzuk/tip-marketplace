from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from NSMManager import NsmManager

# Consts
# Provider Sign.
ACTION_SCRIPT_NAME = 'Unblock IP'
NSM_PROVIDER = 'McAfeeNSM'
ADDRESS = EntityTypes.ADDRESS


@output_handler
def main():
    # Define variables.
    unblocked_entities = []
    result_value = False
    # Configuration.
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_SCRIPT_NAME
    conf = siemplify.get_configuration(NSM_PROVIDER)
    nsm_manager = NsmManager(conf['API Root'], conf['Username'], conf['Password'], conf['Domain ID'],
                             conf['Siemplify Policy Name'], conf['Sensors Names List Comma Separated'])
    # Fetch Scope entities.
    scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type == ADDRESS]

    # Scan entities.
    for entity in scope_entities:
        try:
            release_status = nsm_manager.release_ip(entity.identifier)
            if release_status:
                unblocked_entities.append(entity)
                result_value = True
        except Exception as err:
            siemplify.LOGGER.error('Error unblocking IP {0}, ERROR: {1}'.format(
                entity.identifier,
                err.message
            ))
            siemplify.LOGGER._log.exception(err)

    # Deploy changes.
    nsm_manager.deploy_changes()

    # Logout from NSM.
    nsm_manager.logout()

    # Form output message
    if unblocked_entities:
        output_message = "Successfully unblocked {0}".format(",".join([entity.identifier for
                                                                       entity in unblocked_entities]))
    else:
        output_message = "No entities were Unblocked."

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
