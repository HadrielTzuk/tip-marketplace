from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
# Imports
from SiemplifyAction import SiemplifyAction
from AlienVaultTIManager import AlienVaultTIManager


@output_handler
def main():
    siemplify = SiemplifyAction()

    # Configuration.
    conf = siemplify.get_configuration('AlienVaultTI')
    api_key = conf['Api Key']
    alienvault = AlienVaultTIManager(api_key)

    # Execute Test Connectivity.
    result = alienvault.test_connectivity()

    if result:
        output_message = "Connection Established."
    else:
        output_message = 'Connection Failed.'

    siemplify.end(output_message, result)


if __name__ == '__main__':
    main()
