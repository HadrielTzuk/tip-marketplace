from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from McAfeeTIEDXLManager import McAfeeTIEDXLManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('McAfeeTIEDXL')
    server_addr = conf["Server Address"]
    broker_ca_bundle_path = conf["Broker CA Bundle Path"]
    cert_file_path = conf["Client Cert File Path"]
    private_key_path = conf["Client Key File Path"]

    mcafee_dxl_manager = McAfeeTIEDXLManager(server_addr,
                                      broker_ca_bundle_path,
                                      cert_file_path,
                                      private_key_path)

    # If no exception occur - then connection is successful
    output_message = "Successfully connected to {server_addr}.".format(
        server_addr=server_addr,
    )
    siemplify.end(output_message, True)


if __name__ == '__main__':
    main()
