from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from McAfeeWebGatewayManager import McAfeeWebGatewayManager


@output_handler
def main():
    siemplify = SiemplifyAction()

    conf = siemplify.get_configuration('McAfeeWebGateway')

    server_address = conf['Server Address']
    username = conf['Username']
    password = conf['Password']

    mwb = McAfeeWebGatewayManager(server_address, username, password)
    mwb.logout()

    # If no exception occur - then connection is successful
    # If the connection is unsuccessful, exception is raised in manager.
    output_message = 'Connected successfully'
    siemplify.end(output_message, 'true')


if __name__ == "__main__":
    main()
