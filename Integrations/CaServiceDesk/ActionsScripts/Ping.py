from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from CaSoapManager import CaSoapManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('CaServiceDesk')
    api_root = conf['Api Root']
    username = conf['Username']
    password = conf['Password']
    
    ca_manager = CaSoapManager(api_root, username, password)

    connection = ca_manager.test_connectivity()

    output_message = "Connection Established" if connection else "Connection Failed"
    result_value = connection
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
