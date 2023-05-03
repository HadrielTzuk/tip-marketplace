from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TenableManager import TenableSecurityCenterManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('TenableSecurityCenter')
    server_address = conf['Server Address']
    username = conf['Username']
    password = conf['Password']
    use_ssl = conf['Use SSL'].lower() == 'true'

    TenableSecurityCenterManager(server_address, username, password, use_ssl)

    siemplify.end("Connected successfully", 'true')


if __name__ == "__main__":
    main()
