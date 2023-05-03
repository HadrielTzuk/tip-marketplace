from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
# Imports
from SiemplifyAction import SiemplifyAction
from A1000MalwareAnalysis import A1000MalwareAnalysisClient


@output_handler
def main():
    siemplify = SiemplifyAction()

    # Configuration.
    conf = siemplify.get_configuration("ReversinglabsA1000")
    server_address = conf['Api Root']
    username = conf['Username']
    password = conf['Password']

    a1000_manager = A1000MalwareAnalysisClient(server_address, username, password)

    connectivity = a1000_manager.test_connectivity()
    output_message = "Connected Successfully"
    siemplify.end(output_message, connectivity)


if __name__ == "__main__":
    main()