from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from PanoramaManager import PanoramaManager
from TIPCommon import extract_configuration_param, extract_action_param
import json

SCRIPT_NAME = u"Panorama - RemoveIpFromGroup"
PROVIDER_NAME = u"Panorama"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # Configuration.
    server_address = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Api Root")
    username = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Username")
    password = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Verify SSL",
                                             default_value=True, input_type=bool)

    # Parameters
    deviceName = extract_action_param(siemplify, param_name=u"Device Name", is_mandatory=True, print_value=True)
    device_group_name = extract_action_param(siemplify, param_name=u"Device Group Name", is_mandatory=True,
                                             print_value=True)
    group = extract_action_param(siemplify, param_name=u"Address Group Name", is_mandatory=True, print_value=True)

    ipsToRemove = set()
    json_results = []
    result_value = u'true'
    output_message = u""
    successful_entities = []
    failed_entities = []

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    for entity in siemplify.target_entities:
        if entity.entity_type == EntityTypes.ADDRESS:
            ipsToRemove.add(entity.identifier)

    if ipsToRemove:
        api = PanoramaManager(server_address, username, password, verify_ssl, siemplify.run_folder)
        for ip in ipsToRemove:
            siemplify.LOGGER.info(u"Process entity: {} Started".format(ip))
            try:
                api.EditBlockedIpsInGroup(deviceName=deviceName, deviceGroupName=device_group_name, groupName=group,
                                          IpsToRemove=[ip])
                successful_entities.append(ip)
                siemplify.LOGGER.info(u"Successfully removed entity: {} from {}".format(ip, group))
            except Exception as error:
                siemplify.LOGGER.error(u"Unable to remove entity: {}. Reason is: {}".format(ip, error))
                failed_entities.append(ip)

        json_results = api.ListAddressesInGroup(deviceName=deviceName,
                                                deviceGroupName=device_group_name,
                                                groupName=group)

        if successful_entities:
            output_message += (u'Successfully removed the following IPs from the Palo Alto Panorama address group '
                               u'\"{}\": {}'.format(group, u"\n".join([entity for entity in successful_entities])))

        if failed_entities:
            output_message += u"\n\nAction was not able to remove the following IPs from the Palo Alto Panorama " \
                              u"address group \"{}\": {}".format(group, u"\n".join([entity for entity in
                                                                                    failed_entities]))

        if not successful_entities:
            output_message = u"No IPs were removed from the Palo Alto Panorama address group \"{}\"".format(group)
            result_value = u'false'

    else:
        output_message = u"No IPs found"
        siemplify.LOGGER.info(output_message)
        result_value = u'false'

    siemplify.result.add_result_json(json.dumps(list(json_results)))
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
