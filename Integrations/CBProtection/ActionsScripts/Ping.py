from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from CarbonBlackProtectionManager import CBProtectionManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    configurations = siemplify.get_configuration('CBProtection')
    server_addr = configurations['Api Root']
    api_key = configurations['Api Key']

    cb_protection = CBProtectionManager(server_addr, api_key)

    # If no exception occur - then connection is successful
    output_message = "Connected successfully to {server_address}.".format(
        server_address=server_addr
    )
    siemplify.end(output_message, True)


if __name__ == '__main__':
    main()
