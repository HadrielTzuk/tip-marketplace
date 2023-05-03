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

    file_list_name = siemplify.parameters["File List Name"]

    file_list = cisco_amp_manager.get_file_list_by_name(file_list_name) or {}

    if file_list.get("items"):
        flat_items = []

        for item in file_list.get("items"):
            # Remove links - irrelevant
            if item.get("links"):
                del item["links"]
            flat_items.append(dict_to_flat(item))

        # Attach file lists in csv
        csv_output = construct_csv(flat_items)
        siemplify.result.add_data_table("Items - {}".format(file_list_name), csv_output)

    siemplify.result.add_result_json(file_list)

    siemplify.end("Successfully found {} items in {}.".format(
        len(file_list.get("items", [])), file_list_name), json.dumps(file_list.get("items")))


if __name__ == '__main__':
    main()
