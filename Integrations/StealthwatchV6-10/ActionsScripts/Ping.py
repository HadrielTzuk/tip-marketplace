from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from Stealthwatch610Manager import StealthwatchManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    configurations = siemplify.get_configuration('StealthwatchV6-10')
    server_address = configurations['Api Root']
    username = configurations['Username']
    password = configurations['Password']

    stealthwatch_manager = StealthwatchManager(server_address, username,
                                               password)

    connectivity = stealthwatch_manager.test_connectivity()
    output_message = "Connected Successfully"
    siemplify.end(output_message, connectivity)


if __name__ == '__main__':
    main()