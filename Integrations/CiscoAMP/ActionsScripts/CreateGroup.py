from SiemplifyUtils import output_handler
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

    cisco_amp_manager = CiscoAMPManager(server_addr, client_id, api_key,
                                        use_ssl)

    group_name = siemplify.parameters["Group Name"]
    group_description = siemplify.parameters["Group Description"]

    response_data = cisco_amp_manager.create_group(group_name, group_description)

    siemplify.result.add_result_json(response_data)
    siemplify.end("Successfully created group {}.".format(group_name), 'true')


if __name__ == '__main__':
    main()
