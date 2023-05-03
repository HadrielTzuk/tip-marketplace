from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from VSphereManager import VSphereManager


@output_handler
def main():
    siemplify = SiemplifyAction()

    # Configuration.
    conf = siemplify.get_configuration("VSphere")
    server_address = conf['Server Address']
    username = conf['Username']
    password = conf['Password']
    port = int(conf['Port'])

    # Connect
    VSphereManager(server_address, username, password, port)

    # If no exception occurred - then connection is successful
    siemplify.end("Successfully connected", 'true')


if __name__ == '__main__':
    main()