from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from WildfireManager import WildfireManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('Wildfire')
    api_key = conf['Api Key']

    # Connect to Wildfire
    wildfire_manager = WildfireManager(api_key)

    # Test connectivity
    connectivity = wildfire_manager.test_connectivity()

    # If no exception occurs - then connection is successful
    siemplify.end("Connected successfully.", connectivity)


if __name__ == "__main__":
    main()