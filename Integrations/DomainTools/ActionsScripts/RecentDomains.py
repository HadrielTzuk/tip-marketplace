from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
# Imports
from SiemplifyAction import *
from DomainToolsManager import DomainToolsManager
from SiemplifyUtils import *


@output_handler
def main():
    # Configurations
    siemplify = SiemplifyAction()
    configuration_settings = siemplify.get_configuration('DomainTools')
    username = configuration_settings['Username']
    api_key = configuration_settings['ApiToken']
    domaintools_manager = DomainToolsManager(username, api_key)

    # Parameters
    string_query = siemplify.parameters['String Query']

    # Variables Definition.
    output_message = ''
    entities_to_update = []
    result_value = False

    res = domaintools_manager.getRecentDomainsByStringQuery(string_query)

    if res:
        # Push entity to entities to update array.
        entities_to_update.append(entity)
        # Convert response dict to flat dict.
        flat_dict_res = dict_to_flat(res)
        # Convert response to CSV format string list.
        csv_res = flat_dict_to_csv(flat_dict_res)
        # Print result table.
        siemplify.result.add_data_table('Result For: {0}'.format(string_query), csv_res)
        # Return true on action result.
        result_value = True
    else:
        pass

    # Organize output message.
    if entities_to_update:
        output_message = 'Found results for: {0}'.format(string_query)
    else:
        output_message = 'No results found.'

    # End action
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
