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

    groups = cisco_amp_manager.get_groups()
    json_results = {}

    if groups:
        flat_groups = []

        for index, group in enumerate(groups):
            # Remove links - irrelevant
            if group.get("links"):
                del group["links"]
            flat_groups.append(dict_to_flat(group))
            json_results[index] = group

        # Attach groups in csv
        csv_output = construct_csv(flat_groups)
        siemplify.result.add_data_table("Groups", csv_output)

    # add json
    siemplify.result.add_result_json(json_results)

    siemplify.end("Successfully found {} groups.".format(len(groups)), json.dumps(groups))


if __name__ == '__main__':
    main()
