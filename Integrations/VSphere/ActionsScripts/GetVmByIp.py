from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from VSphereManager import VSphereManager
from SiemplifyUtils import convert_dict_to_json_result_dict
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

    vsphere_manager = VSphereManager(server_address, username, password, port)

    vms = {}

    for entity in siemplify.target_entities:
        if entity.entity_type == EntityTypes.ADDRESS:
            vms[entity.identifier] = vsphere_manager.get_vm_info(
                vsphere_manager.get_vm_by_ip(entity.identifier)
            )

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(vms))

    siemplify.end("Vsphere - Found the following vms: \n" +
                  "\n".join(["{}: {}".format(ip, vm["Name"]) for ip, vm in vms.items()]),
                  'true')


if __name__ == '__main__':
    main()