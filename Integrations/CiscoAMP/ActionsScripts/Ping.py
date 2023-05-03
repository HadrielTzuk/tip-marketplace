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

    cisco_amp_manager.test_connectivity()

    # If no exception occur - then connection is successful
    output_message = "Connected successfully to {server_address}.".format(
        server_address=server_addr
    )
    siemplify.end(output_message, True)


if __name__ == '__main__':
    main()
