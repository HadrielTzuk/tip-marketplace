from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from McAfeeWebGatewayManager import McAfeeWebGatewayManager


@output_handler
def main():
    siemplify = SiemplifyAction()

    conf = siemplify.get_configuration('McAfeeWebGateway')

    server_address = conf['Server Address']
    username = conf['Username']
    password = conf['Password']

    result_value = 'false'
    group_name = siemplify.parameters['Group Name']
    item_to_delete = siemplify.parameters['Item To Delete']

    mwb = McAfeeWebGatewayManager(server_address, username, password)

    res = mwb.delete_entry_from_list_by_name(group_name, item_to_delete)

    if res:
        result_value = 'true'
        output_message = 'Item {0} was deleted successfully from {1}'.format(item_to_delete, group_name)
    else:
        output_message = 'Failed to delete {0} item from {1}. No changes made.'.format(item_to_delete, group_name)

    mwb.logout()
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
