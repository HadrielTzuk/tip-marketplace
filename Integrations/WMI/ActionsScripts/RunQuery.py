from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifySdkConfig import SiemplifySdkConfig
from SiemplifyAction import SiemplifyAction
from WMIManager import WMIManagerBuilder
import json


@output_handler
def main():
    siemplify = SiemplifyAction()
    server_addr = siemplify.parameters['Server Address']
    username = siemplify.parameters.get('Username')
    password = siemplify.parameters.get('Password')
    query = siemplify.parameters['WQL Query']

    wmi_manager = WMIManagerBuilder.create_manager(server_addr, username, password, SiemplifySdkConfig.is_linux())

    items = wmi_manager.run_query(query)
    siemplify.result.add_result_json(json.dumps(items or []))

    if items:
        csv_output = wmi_manager.construct_csv(items)
        siemplify.result.add_data_table("WMI Query Results", csv_output)

        output_message = "Successfully ran query."
        siemplify.end(output_message, json.dumps(items))

    else:
        output_message = "No results from query."
        siemplify.end(output_message, 'false')


if __name__ == '__main__':
    main()
