from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from RSAArcherManager import RSAArcherManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration("RSAArcher")
    server_address = conf["Api Root"]
    username = conf["Username"]
    password = conf["Password"]
    instance_name = conf["Instance Name"]
    verify_ssl = conf.get('Verify SSL', 'False').lower() == 'true'

    archer_manager = RSAArcherManager(server_address,
                                      username,
                                      password,
                                      instance_name,
                                      verify_ssl,
                                      siemplify.LOGGER)

    siemplify.end("Connected successfully.", 'true')


if __name__ == '__main__':
    main()