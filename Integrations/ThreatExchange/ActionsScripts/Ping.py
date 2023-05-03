from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ThreatExchangeManager import ThreatExchangeManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = 'ThreatExchange - GetFileReputation'

    conf = siemplify.get_configuration('ThreatExchange')
    server_addr = conf['Api Root']
    app_id = conf['App ID']
    app_secret = conf['App Secret']
    api_version = conf['API Version']
    use_ssl = conf['Use SSL'].lower() == 'true'

    threat_exchange_manager = ThreatExchangeManager(server_addr, app_id, app_secret, api_version, use_ssl)
    threat_exchange_manager.test_connectivity()

    # If no exception occur - then connection is successful
    output_message = "Connected successfully to {server_address}.".format(
        server_address=server_addr
    )
    siemplify.end(output_message, True)


if __name__ == '__main__':
    main()
