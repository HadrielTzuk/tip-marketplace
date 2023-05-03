from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from McAfeeWebGatewayManager import McAfeeWebGatewayManager

# Consts
SCRIPT_NAME = "McAfeeWebGateway - BlockIP"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration('McAfeeWebGateway')

    server_address = conf['Server Address']
    username = conf['Username']
    password = conf['Password']

    mwb = McAfeeWebGatewayManager(server_address, username, password)

    group_name = siemplify.parameters['Group Name']

    success_list = []
    failed_list = []
    output_message = ''
    result_value = 'true'

    for entity in siemplify.target_entities:
        if entity.entity_type == EntityTypes.ADDRESS:
            try:
                res = mwb.delete_entry_from_list_by_name(group_name, '{0}/32'.format(entity.identifier))
                if res:
                    success_list.append(entity.identifier)
                else:
                    failed_list.append(entity.identifier)
            except Exception as e:
                # An error occurred - skip entity and continue
                siemplify.LOGGER.error("Entity: {}. Error: {}.".format(entity.identifier, str(e)))
                siemplify.LOGGER._log.exception(e)

    if success_list:
        output_message += 'Following IPs were successfully unblocked:\n{}\n\n'.format(
            '\n'.join(success_list))
    if failed_list:
        result_value = 'false'
        output_message += 'Failed to unblock following IPs:\n{}\n\n'.format(
            '\n'.join(failed_list))
    if not failed_list and not success_list:
        result_value = 'false'
        output_message = 'No changes made.'

    mwb.logout()
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
