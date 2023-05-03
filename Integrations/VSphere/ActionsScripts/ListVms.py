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

    # Connect
    vsphere_manager = VSphereManager(server_address, username, password, port)

    vms = vsphere_manager.get_all_vms()
    vms_info = []
    vm_names = []
    for vm in vms:
        vm_names.append(vm.name)
        vms_info.append(VSphereManager.get_vm_info(vm))

    csv_output = VSphereManager.construct_csv(vms_info)

    siemplify.result.add_data_table("Vms Info", csv_output)
    siemplify.result.add_result_json(json.dumps(vms_info))

    siemplify.end("Found {} vms".format(len(vms)), json.dumps(vm_names))


if __name__ == '__main__':
    main()