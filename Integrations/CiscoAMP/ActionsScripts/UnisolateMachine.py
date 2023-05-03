from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import convert_dict_to_json_result_dict
from CiscoAMPManager import CiscoAMPManager

SCRIPT_NAME = u"CiscoAMP - UnisolateMachine"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    configurations = siemplify.get_configuration(u'CiscoAMP')
    server_address = configurations[u'Api Root']
    client_id = configurations[u'Client ID']
    api_key = configurations[u'Api Key']
    use_ssl = configurations[u'Use SSL'].lower() == u'true'

    manager = CiscoAMPManager(server_address, client_id, api_key, use_ssl)

    enriched_entities = []
    json_results = {}
    errors = u""

    for entity in siemplify.target_entities:
        try:
            computer = None
            if entity.entity_type == EntityTypes.ADDRESS:
                computer = manager.get_computer_info_by_ip(
                    entity.identifier, internal=entity.is_internal)

            elif entity.entity_type == EntityTypes.HOSTNAME:
                computer = manager.get_computer_info_by_hostname(entity.identifier)

            if computer:
                info = manager.unisolate_machine(computer[u'connector_guid'])
                json_results[entity.identifier] = info
                enriched_entities.append(entity)
            else:
                siemplify.LOGGER.info(u"Computer was not found for entity {}".format(entity.identifier))

        except Exception as e:
            errors += u"Unable to unisolate computer by ip {0}: \n{1}\n".format(
                entity.identifier, unicode(e))
            continue

    if enriched_entities:
        entities_names = [entity.identifier for entity in enriched_entities]
        output_message = u'The following computers unisolated successfully:\n{}\n'.format('\n'.join(
            entities_names))
        output_message += errors

        siemplify.update_entities(enriched_entities)

    else:
        output_message = u'Cisco AMP - No computers were found to unisolate.\n'
        output_message += errors

    # add json
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.end(output_message, u'true')


if __name__ == '__main__':
    main()
