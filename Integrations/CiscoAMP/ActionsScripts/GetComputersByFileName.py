from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import construct_csv
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

    enriched_entities = []
    json_results = {}
    errors = ""

    for entity in siemplify.target_entities:
        try:
            if entity.entity_type == EntityTypes.FILENAME:
                computers = cisco_amp_manager.get_computer_activity(
                    entity.identifier)

                if computers:
                    flat_computers = []
                    computers_dict = {}

                    for index, computer in enumerate(computers):
                        computers_dict[index] = computer
                        # Remove links (not relevant)
                        del computer["links"]

                        computer_info = cisco_amp_manager.create_computer_info(
                            computer)

                        flat_computers.append(computer_info)

                    # Attach file lists in csv
                    csv_output = construct_csv(
                        flat_computers)
                    siemplify.result.add_data_table("Computers", csv_output)

                    enriched_entities.append(entity)
                    json_results[entity.identifier] = computers_dict

        except Exception as e:
            errors += "Unable to get computer by file {0}: \n{1}\n".format(
                entity.identifier, e.message)
            continue

    if enriched_entities:
        entities_names = [entity.identifier for entity in enriched_entities]
        output_message = 'Cisco AMP - Got computers by the following files\n' + '\n'.join(
            entities_names)
        output_message += errors

        siemplify.update_entities(enriched_entities)

    else:
        output_message = 'Cisco AMP - No computers were found.\n'
        output_message += errors

    # add json
    siemplify.result.add_result_json(json_results)
    siemplify.end(output_message, 'true')


if __name__ == '__main__':
    main()
