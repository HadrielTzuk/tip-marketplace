from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from NSMManager import NsmManager

# Consts
# Provider Sign.
NSM_PROVIDER = 'McAfeeNSM'
ADDRESS = EntityTypes.ADDRESS


@output_handler
def main():
    # Define Variables.
    blocked_entitites = []
    unblocked_entities = []
    result_value = False
    # configurations.
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration(NSM_PROVIDER)
    nsm_manager = NsmManager(conf['API Root'], conf['Username'], conf['Password'], conf['Domain ID'],
                             conf['Siemplify Policy Name'], conf['Sensors Names List Comma Separated'])

    # Fetch scope entities.
    scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type == ADDRESS]

    # Run on entities.
    for entity in scope_entities:
        # Check if address blocked.
        block_status = nsm_manager.is_ip_blocked(entity.identifier)
        if block_status:
            blocked_entitites.append(entity)
            result_value = True
        else:
            unblocked_entities.append(entity)

    # Logout from NSM.
    nsm_manager.logout()

    # Form output message.
    if scope_entities:
        output_message = "Blocked Entities: {0} \n Unblocked Entities: {1}".format(",".join(map(str, blocked_entitites)),
                                                                                   ",".join(map(str, unblocked_entities)))
    else:
        output_message = "No entities with type address at the case."

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
