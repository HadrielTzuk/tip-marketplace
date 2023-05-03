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

    services = wmi_manager.get_services()
    siemplify.result.add_result_json(json.dumps(services or []))

    if services:
        csv_output = wmi_manager.construct_csv(services)
        siemplify.result.add_data_table("WMI Services", csv_output)

        output_message = "Found {} services".format(len(services))
        siemplify.end(output_message, json.dumps(services))

    else:
        output_message = "No services were found."
        siemplify.end(output_message, 'false')


if __name__ == '__main__':
    main()
