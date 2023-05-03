from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifySdkConfig import SiemplifySdkConfig
from WMIManager import WMIManagerBuilder
import json


@output_handler
def main():
    siemplify = SiemplifyAction()
    server_addr = siemplify.parameters['Server Address']
    username = siemplify.parameters.get('Username')
    password = siemplify.parameters.get('Password')

    wmi_manager = WMIManagerBuilder.create_manager(server_addr, username, password, SiemplifySdkConfig.is_linux())

    users = wmi_manager.get_users()
    siemplify.result.add_result_json(json.dumps(users or []))

    if users:
        csv_output = wmi_manager.construct_csv(users)
        siemplify.result.add_data_table("WMI Users", csv_output)

        output_message = "Found {} users".format(len(users))
        siemplify.end(output_message, json.dumps(users))

    else:
        output_message = "No users were found."
        siemplify.end(output_message, 'false')


if __name__ == '__main__':
    main()