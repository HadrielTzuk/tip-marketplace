from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from McAfeeWebGatewayManager import McAfeeWebGatewayManager

# Consts
DESCRIPTION = 'Added by Siemplify'


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('McAfeeWebGateway')

    server_address = conf['Server Address']
    username = conf['Username']
    password = conf['Password']

    group_name = siemplify.parameters['Group Name']
    item_to_insert = siemplify.parameters.get('Item To Insert')
    description = siemplify.parameters.get('Description') or DESCRIPTION

    mwb = McAfeeWebGatewayManager(server_address, username, password)

    res = mwb.insert_entry_to_list_by_name(group_name, item_to_insert, description)
    if res:
        output_message = 'Successfully added {0} to {1}'.format(item_to_insert, group_name)
        result_value = 'true'
    else:
        output_message = 'Failed added {0} to {1}'.format(item_to_insert, group_name)
        result_value = 'false'

    mwb.logout()
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
