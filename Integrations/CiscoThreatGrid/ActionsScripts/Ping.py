from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CiscoThreatGridManager import CiscoThreatGridManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = 'CiscoThreatGrid - GetSubmissions'

    conf = siemplify.get_configuration('CiscoThreatGrid')
    server_addr = conf['Api Root']
    api_key = conf['Api Key']
    use_ssl = conf['Use SSL'].lower() == 'true'
    cisco_threat_grid = CiscoThreatGridManager(server_addr, api_key, use_ssl)

    cisco_threat_grid.test_connectivity()

    # If no exception occur - then connection is successful
    output_message = "Connected successfully to {server_address}.".format(
        server_address=server_addr
    )
    siemplify.end(output_message, True)


if __name__ == '__main__':
    main()
