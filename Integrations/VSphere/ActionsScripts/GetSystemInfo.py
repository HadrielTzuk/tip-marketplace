from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import flat_dict_to_csv
from VSphereManager import VSphereManager
import json


@output_handler
def main():
    siemplify = SiemplifyAction()

    # Configuration.
    conf = siemplify.get_configuration("VSphere")
    server_address = conf['Server Address']
    username = conf['Username']
    password = conf['Password']
    port = int(conf['Port'])

    vm_name = siemplify.parameters['Vm Name']

    # Connect
    vsphere_manager = VSphereManager(server_address, username, password, port)

    vm = vsphere_manager.get_obj_by_name(vm_name)
    vm_info = VSphereManager.get_vm_info(vm)

    csv_output = flat_dict_to_csv(vm_info)
    siemplify.result.add_data_table("{} Info".format(vm.name), csv_output)

    siemplify.result.add_result_json(json.dumps(vm_info))
    siemplify.end("Successfully fetched information on {}".format(vm.name), json.dumps(vm_info))


if __name__ == '__main__':
    main()