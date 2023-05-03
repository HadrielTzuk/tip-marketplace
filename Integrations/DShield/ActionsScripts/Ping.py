from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
# Imports
from SiemplifyAction import SiemplifyAction
from DShieldManager import DShieldManager


@output_handler
def main():
    siemplify = SiemplifyAction()

    # Configuration.
    conf = siemplify.get_configuration('DShield')
    api_root = conf['Api Root']
    dshield = DShieldManager(api_root)

    # Execute Test Connectivity.
    result = dshield.test_connectivity()

    if result:
        output_message = "Connection Established."
        result_value = 'true'
    else:
        output_message = 'Connection Failed.'
        result_value = 'false'

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
