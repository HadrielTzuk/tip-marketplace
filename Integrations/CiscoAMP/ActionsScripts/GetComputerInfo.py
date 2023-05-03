from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import dict_to_flat, add_prefix_to_dict, flat_dict_to_csv, convert_dict_to_json_result_dict
from CiscoAMPManager import CiscoAMPManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    configurations = siemplify.get_configuration('CiscoAMP')
    server_addr = configurations['Api Root']
    client_id = configurations['Client ID']
    api_key = configurations['Api Key']
    use_ssl = configurations['Use SSL'].lower() == 'true'

    cisco_amp_manager = CiscoAMPManager(server_addr, client_id, api_key,
                                        use_ssl)

    enriched_entities = []
    json_results = {}
    errors = ""

    for entity in siemplify.target_entities:
        try:
            computer = None

            if entity.entity_type == EntityTypes.ADDRESS:
                computer = cisco_amp_manager.get_computer_info_by_ip(
                    entity.identifier, internal=entity.is_internal)

            elif entity.entity_type == EntityTypes.HOSTNAME:
                computer = cisco_amp_manager.get_computer_info_by_hostname(entity.identifier)

            if computer:
                json_results[entity.identifier] = computer

                # Remove links (not relevant)
                del computer["links"]

                # Enrich the entity with the data
                flat_computer = dict_to_flat(computer)
                flat_computer = add_prefix_to_dict(flat_computer, "CiscoAMP")
                entity.additional_properties.update(flat_computer)

                computer_info = cisco_amp_manager.create_computer_info(computer)

                # Attach as csv
                csv_output = flat_dict_to_csv(computer_info)
                siemplify.result.add_entity_table(entity.identifier,
                                                  csv_output)

                enriched_entities.append(entity)

        except Exception as e:
            errors += u"Unable to get computer info of {0}: \n{1}\n".format(
                entity.identifier, e.message)
            continue

    if enriched_entities:
        entities_names = [entity.identifier for entity in enriched_entities]
        output_message = 'Cisco AMP - Enriched the following entities\n' + '\n'.join(
            entities_names)
        output_message += errors

        siemplify.update_entities(enriched_entities)

    else:
        output_message = 'Cisco AMP - No entities were enriched.\n'
        output_message += errors

    # add json
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.end(output_message, 'true')


if __name__ == '__main__':
    main()
