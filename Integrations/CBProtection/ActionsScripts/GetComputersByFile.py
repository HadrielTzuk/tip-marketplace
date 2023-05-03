from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from CarbonBlackProtectionManager import CBProtectionManager, CBProtectionManagerException
from SiemplifyUtils import convert_dict_to_json_result_dict
import json


@output_handler
def main():
    siemplify = SiemplifyAction()
    configurations = siemplify.get_configuration('CBProtection')
    server_addr = configurations['Api Root']
    api_key = configurations['Api Key']

    cb_protection = CBProtectionManager(server_addr, api_key)

    enriched_entities = []
    computer_infos = []
    json_result = {}
    errors = ""

    for entity in siemplify.target_entities:
        try:
            if entity.entity_type == EntityTypes.FILEHASH:
                # CR: Move to manager
                if len(entity.identifier) == 32:
                    computers = cb_protection.get_computers_running_hash(entity.identifier)

                    if computers:
                        # CR: Move to manager
                        for computer in computers:
                            computer_info = {
                                "Id": computer.get('id'),
                                "Hostname": computer.get("name"),
                                "Mac Address": computer.get("macAddress"),
                                "Ip Address": computer.get("ipAddress"),
                                "Policy Name": computer.get("policyName"),
                                "Connected": computer.get("connected"),
                                "Operating System": computer.get("osName"),
                                "Last Updated": computer.get("last_update"),
                                "Agent Version": computer.get(
                                    "agentVersion	"),
                            }
                            computer_infos.append(computer_info)

                        json_result[entity.identifier] = [computer.original_document for computer in computers]

                        # Attach as csv
                        csv_output = cb_protection.construct_csv(computer_infos)
                        siemplify.result.add_entity_table(entity.identifier, csv_output)
                        enriched_entities.append(entity)

        except Exception as e:
            errors += "Unable to get computer that are running file {0}: \n{1}\n".format(
                entity.identifier, e.message)
            continue

    if enriched_entities:
        entities_names = [entity.identifier for entity in enriched_entities]
        output_message = 'Carbon Black Protection - Found computers for the following files:\n' + '\n'.join(
            entities_names)
        output_message += errors

    else:
        output_message = 'Carbon Black Protection - No computers were found.\n'
        output_message += errors

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_result))
    siemplify.end(output_message, 'true')


if __name__ == '__main__':
    main()
