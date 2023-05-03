from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from VSphereManager import VSphereManager


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

    # Power on vm
    vm =  vsphere_manager.get_obj_by_name(vm_name)
    vsphere_manager.reset_vm(vm)

    siemplify.end("Successfully reset {}".format(vm.name), 'true')


if __name__ == '__main__':
    main()