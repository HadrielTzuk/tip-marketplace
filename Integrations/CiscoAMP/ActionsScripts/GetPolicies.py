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

    policies = cisco_amp_manager.get_policies()
    json_results = {}

    if policies:
        flat_policies = []

        for index, policy in enumerate(policies):
            # Remove links - irrelevant
            if policy.get("links"):
                del policy["links"]
            flat_policies.append(dict_to_flat(policy))
            json_results[index] = policy

        # Attach policies in csv
        csv_output = construct_csv(flat_policies)
        siemplify.result.add_data_table("Policies", csv_output)

    # add json
    siemplify.result.add_result_json(json_results)

    siemplify.end("Successfully found {} policies.".format(len(policies)), json.dumps(policies))


if __name__ == '__main__':
    main()
