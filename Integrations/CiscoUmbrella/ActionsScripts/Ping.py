from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
# Imports
from SiemplifyAction import  SiemplifyAction
from CiscoUmbrellaManager import  CiscoUmbrellaIvestigate


@output_handler
def main():
    # Define Variables
    result_value = 'false'
    # Define SiemplifyAction object
    siemplify = SiemplifyAction()

    # Configuration.
    conf = siemplify.get_configuration('CiscoUmbrella')
    token = conf['InvestigateApiToken']
    cisco_umbrella_manager = CiscoUmbrellaIvestigate(token)

    # Check Connectivity
    if cisco_umbrella_manager.ping():
        output_message = 'Connection Established.'
        result_value = 'true'
    else:
        output_message = 'Connection Failed.'

    # End Action
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
