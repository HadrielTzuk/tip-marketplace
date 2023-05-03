from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import construct_csv, dict_to_flat
from SysAidManager import SysAidManager
import json


PROVIDER = "SysAid"
ACTION_NAME = "SysAid - ListUsers"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.action_definition_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    verify_ssl = conf.get('Verify SSL').lower() == 'true'
    sysaid_manager = SysAidManager(server_address=conf.get('Api Root'),
                                           username=conf.get('Username'),
                                           password=conf.get('Password'),
                                           verify_ssl=verify_ssl)

    users = sysaid_manager.get_users()

    output_message = "Found {} users".format(len(users))

    if users:
        flat_users = map(dict_to_flat, users)
        csv_output = construct_csv(flat_users)
        siemplify.result.add_data_table("SysAid - Users", csv_output)

    siemplify.end(output_message, json.dumps(users))


if __name__ == "__main__":
    main()