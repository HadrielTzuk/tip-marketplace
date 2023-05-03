from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from CylanceManager import CylanceManager

SCRIPT_NAME = "Cylance - DeleteFromGlobalList"


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

    list_type = siemplify.parameters.get('List Type')

    affected_entities = []

    for entity in siemplify.target_entities:
        try:
            if entity.entity_type == EntityTypes.FILEHASH:
                cm.delete_from_global_list(entity.identifier, list_type=list_type)
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

        output_message = 'Following hashes were deleted from "{}":\n{}'.format(
            list_type, '\n'.join(entities_names))

    else:
        output_message = 'No hash was deleted from the global list "{}"\n'.format(
            list_type)

    siemplify.end(output_message, 'true')


if __name__ == "__main__":
    main()
