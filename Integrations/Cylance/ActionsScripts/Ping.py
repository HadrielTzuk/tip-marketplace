from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CylanceManager import CylanceManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('Cylance')

    server_address = conf['Server Address']
    application_secret = conf['Application Secret']
    application_id = conf['Application ID']
    tenant_identifier = conf['Tenant Identifier']

    cm = CylanceManager(server_address, application_id, application_secret,
                        tenant_identifier)

    siemplify.end("Successfully connected.", 'true')


if __name__ == "__main__":
    main()
