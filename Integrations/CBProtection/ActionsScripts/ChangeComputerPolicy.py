from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import dict_to_flat, add_prefix_to_dict, flat_dict_to_csv
from CarbonBlackProtectionManager import CBProtectionManager, \
    CBProtectionManagerException


@output_handler
def main():
    siemplify = SiemplifyAction()
    configurations = siemplify.get_configuration('CBProtection')
    server_addr = configurations['Api Root']
    api_key = configurations['Api Key']

    cb_protection = CBProtectionManager(server_addr, api_key)

    policy_name = siemplify.parameters.get('Policy Name')

    enriched_entities = []
    errors = ""

    for entity in siemplify.target_entities:
        try:
            computer = None

            if entity.entity_type == EntityTypes.ADDRESS:
                computer = cb_protection.get_computer_by_ip(entity.identifier)

            elif entity.entity_type == EntityTypes.HOSTNAME:
                computer = cb_protection.get_computer_by_hostname(
                    entity.identifier)

            if computer:
                cb_protection.change_computer_policy(computer.id, policy_name)
                enriched_entities.append(entity)

        except Exception as e:
            errors += "Unable to change policy of {0}: \n{1}\n".format(
                entity.identifier, e.message)
            continue

    if enriched_entities:
        entities_names = [entity.identifier for entity in enriched_entities]
        output_message = 'Carbon Black Protection - The following computer were moved to policy {}:\n'.format(
            policy_name) + '\n'.join(entities_names)
        output_message += errors

        siemplify.update_entities(enriched_entities)

    else:
        output_message = 'Carbon Black Protection - No computers were moved to policy {}.\n'.format(policy_name)
        output_message += errors

    siemplify.end(output_message, 'true')


if __name__ == '__main__':
    main()
