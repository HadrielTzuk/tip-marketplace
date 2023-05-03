from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import dict_to_flat, construct_csv
from CiscoAMPManager import CiscoAMPManager
import json


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

    policy_name = siemplify.parameters["Policy Name"]

    policy_info = cisco_amp_manager.get_policy_by_name(policy_name)
    json_results = {}

    if policy_info.get("file_lists"):
        flat_file_lists = []

        for index, file_list in enumerate(policy_info.get("file_lists")):
            # Remove links - irrelevant
            if file_list.get("links"):
                del file_list["links"]

            flat_file_lists.append(dict_to_flat(file_list))
            json_results[index] = file_list

        # Attach file lists in csv
        csv_output = construct_csv(flat_file_lists)
        siemplify.result.add_data_table("File Lists", csv_output)

    siemplify.result.add_result_json(json_results)

    siemplify.end("Successfully found {} file lists.".format(
        len(policy_info.get("file_lists", []))), json.dumps(policy_info.get("file_lists")))


if __name__ == '__main__':
    main()
