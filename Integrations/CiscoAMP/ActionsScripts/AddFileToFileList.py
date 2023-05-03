from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from CiscoAMPManager import CiscoAMPManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    configurations = siemplify.get_configuration('CiscoAMP')
    server_addr = configurations['Api Root']
    client_id = configurations['Client ID']
    api_key = configurations['Api Key']
    use_ssl = configurations['Use SSL'].lower() == 'true'

    cisco_amp_manager = CiscoAMPManager(server_addr, client_id, api_key, use_ssl)

    description = siemplify.parameters["Description"]
    file_list_name = siemplify.parameters["File List Name"]
    file_list = cisco_amp_manager.get_file_list_by_name(file_list_name)

    enriched_entities = []
    errors = ""

    for entity in siemplify.target_entities:
        try:
            if entity.entity_type == EntityTypes.FILEHASH:
                # Only SHA256
                if len(entity.identifier) == 64:
                    cisco_amp_manager.add_file_to_list(file_list["guid"],
                                                       entity.identifier,
                                                       description)
                    enriched_entities.append(entity)
        except Exception as e:
            errors += "Unable to add hash {0} to file list {1}: \n{2}\n".format(
                entity.identifier, file_list_name, e.message)
            continue

    if enriched_entities:
        entities_names = [entity.identifier for entity in enriched_entities]
        output_message = 'Cisco AMP - Added the following hashes to {}:\n'.format(file_list_name) + '\n'.join(
            entities_names)
        output_message += errors

        siemplify.update_entities(enriched_entities)

    else:
        output_message = 'Cisco AMP - No files were added to {}.\n'.format(file_list_name)
        output_message += errors

    siemplify.end(output_message, 'true')


if __name__ == '__main__':
    main()
