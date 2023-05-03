from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
# Imports
from SiemplifyAction import SiemplifyAction
from TitaniumCloud import TitaniumCloudClient


@output_handler
def main():
    siemplify = SiemplifyAction()

    # Configuration.
    conf = siemplify.get_configuration("ReversinglabsTitanium")
    server_address = conf['Api Root']
    username = conf['Username']
    password = conf['Password']

    titanium_manager = TitaniumCloudClient(server_address, username, password)
    
    connectivity = titanium_manager.test_connectivity()
    output_message = "Connected Successfully"
    siemplify.end(output_message, connectivity)

    
if __name__ == "__main__":
    main()