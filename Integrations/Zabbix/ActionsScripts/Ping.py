from SiemplifyUtils import output_handler
from SiemplifyAction import *
from ZabbixManager import ZabbixManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    configurations = siemplify.get_configuration('Zabbix')
    server_addr = configurations['Api Root']
    username = configurations['Username']
    password = configurations['Password']
    verify_ssl = configurations.get('Verify SSL', 'False').lower() == 'true'

    zabbix = ZabbixManager(server_addr, username, password, verify_ssl)

    # If no exception occur - then connection is successful
    output_message = "Connected successfully to {server_address}.".format(
        server_address=server_addr
    )
    siemplify.end(output_message, True)


if __name__ == '__main__':
    main()
