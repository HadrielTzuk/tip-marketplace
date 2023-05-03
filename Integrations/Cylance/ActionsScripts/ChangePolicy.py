from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from CylanceManager import CylanceManager

SCRIPT_NAME = "Cylance - ChangePolicy"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration('Cylance')

    server_address = conf['Server Address']
    application_secret = conf['Application Secret']
    application_id = conf['Application ID']
    tenant_identifier = conf['Tenant Identifier']

    cm = CylanceManager(server_address, application_id, application_secret,
                        tenant_identifier)

    policy_name = siemplify.parameters.get('Policy Name')

    affected_entities = []

    for entity in siemplify.target_entities:
        try:
            if entity.entity_type == EntityTypes.ADDRESS:
                device_id = cm.get_device_by_name(entity.identifier, is_address=True)
                cm.change_device_policy(device_id, policy_name)

                affected_entities.append(entity)

            elif entity.entity_type == EntityTypes.HOSTNAME:
                device_id = cm.get_device_by_name(entity.identifier)
                cm.change_device_policy(device_id, policy_name)

                affected_entities.append(entity)

        except Exception as e:
            # An error occurred - skip entity and continue
            siemplify.LOGGER.error(
                "An error occurred on entity: {}.\n{}.".format(
                    entity.identifier, str(e)
                ))
            siemplify.LOGGER._log.exception(e)

    if affected_entities:
        entities_names = [entity.identifier for entity in affected_entities]

        output_message = 'Policy {} was changed for:\n'.format(
            policy_name) + '\n'.join(entities_names)

    else:
        output_message = 'No entities were affected.'

    siemplify.end(output_message, 'true')


if __name__ == "__main__":
    main()
