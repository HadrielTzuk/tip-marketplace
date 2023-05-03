from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from CylanceManager import CylanceManager

SCRIPT_NAME = u"Cylance - AddToGlobalList"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration(u'Cylance')

    server_address = conf[u'Server Address']
    application_secret = conf[u'Application Secret']
    application_id = conf[u'Application ID']
    tenant_identifier = conf[u'Tenant Identifier']

    cm = CylanceManager(server_address, application_id, application_secret,
                        tenant_identifier)

    list_type = siemplify.parameters.get(u'List Type')
    category = siemplify.parameters.get(u'Category')
    reason = siemplify.parameters.get(u'Reason') if siemplify.parameters.get(u'Reason') else u'None'

    output_message = u""
    affected_entities = []
    failed_entities = []
    existing_entities = []

    for entity in siemplify.target_entities:
        try:
            if entity.entity_type == EntityTypes.FILEHASH:
                if cm.add_to_global_list(entity.identifier, list_type=list_type, category=category, reason=reason):
                    affected_entities.append(entity)
                else:
                    existing_entities.append(entity)

        except Exception as e:
            # An error occurred - skip entity and continue
            siemplify.LOGGER.error(
                u"An error occurred on entity: {}.\n{}.".format(
                    entity.identifier, str(e)
                ))
            failed_entities.append(entity)
            siemplify.LOGGER._log.exception(e)

    if affected_entities:
        entities_names = [entity.identifier for entity in affected_entities]

        output_message += u'\nFollowing hashes were added to {}:\n{}'.format(
            list_type, u'\n'.join(entities_names))
    else:
        output_message += u'\nNo hash was added to the global list "{}"\n'.format(
            list_type)
    if existing_entities:
        entities_names = [entity.identifier for entity in existing_entities]

        output_message += u'\nThere have already an entry for these threats in {}:\n{}'.format(
            list_type, u'\n'.join(entities_names))

    if failed_entities:
        entities_names = [entity.identifier for entity in failed_entities]

        output_message += u'\nFollowing hashes failed to added {}:\n{}'.format(
            list_type, u'\n'.join(entities_names))

    siemplify.end(output_message, u'true')


if __name__ == "__main__":
    main()
