from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from AlienVaultManager import AlienVaultManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    configurations = siemplify.get_configuration('AlienVaultAppliance')
    server_address = configurations['Api Root']
    username = configurations['Username']
    password = configurations['Password']

    alienvault_manager = AlienVaultManager(server_address, username, password)

    # If no exception occur - then connection is successful
    output_message = "Connected successfully."

    siemplify.end(output_message, 'true')


if __name__ == '__main__':
    main()
