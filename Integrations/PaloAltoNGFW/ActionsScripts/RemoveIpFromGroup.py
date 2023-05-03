from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from NGFWManager import NGFWManager, GroupNotExistsException
from TIPCommon import extract_configuration_param, extract_action_param
import json
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

INTEGRATION_NAME = u"PaloAltoNGFW"
SUPPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"NGFW - RemoveIpFromGroup"
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Root",
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           print_value=False)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                           print_value=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)
    device_name = extract_action_param(siemplify, param_name=u"Device Name", print_value=True)
    vsys_name = extract_action_param(siemplify, param_name=u"Vsys Name", print_value=True)
    group = extract_action_param(siemplify, param_name=u"Address Group Name", print_value=True, is_mandatory=True)
    use_shared_objects = extract_action_param(siemplify, param_name=u"Use Shared Objects", print_value=True,
                                              input_type=bool)

    output_message = u''
    status = EXECUTION_STATE_COMPLETED
    successful_entities, not_existing_entities = [], []
    json_results = {}
    result_value = True
    suitable_entity_identifiers = [entity.identifier for entity in siemplify.target_entities
                                   if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        if not use_shared_objects and (not device_name or not vsys_name):
            raise Exception(u'Either "Use Shared Objects" parameter should be enabled or "Device name" '
                            'and "Vsys name" to be provided.')

        api = NGFWManager(api_root, username, password, siemplify.run_folder, siemplify.LOGGER, verify_ssl=verify_ssl)

        if not use_shared_objects:
            ip_addresses_from_group = list(api.ListAddressesInGroup(deviceName=device_name, vsysName=vsys_name,
                                                                    groupName=group)) or []
            for entity_identifier in suitable_entity_identifiers:
                if entity_identifier not in ip_addresses_from_group:
                    not_existing_entities.append(entity_identifier)
                else:
                    api.EditBlockedIpsInGroup(deviceName=device_name, vsysName=vsys_name, groupName=group,
                                              IpsToRemove=[entity_identifier])
                    successful_entities.append(entity_identifier)

        else:
            ip_addresses_from_group = api.ListSharedAddressesFromGroup(group_name=group)
            not_existing_entities = [address for address in suitable_entity_identifiers
                                     if address not in ip_addresses_from_group]
            stay_ip_addresses = [address for address in ip_addresses_from_group
                                 if address not in suitable_entity_identifiers]
            removable_entities = [address for address in ip_addresses_from_group
                                  if address in suitable_entity_identifiers]

            for entity_identifier in removable_entities:
                api.EditSharedIpsInGroup(group_name=group, entity_identifier=entity_identifier, action=u'delete')
                successful_entities.append(entity_identifier)

            for entity_identifier in stay_ip_addresses:
                api.EditSharedIpsInGroup(group_name=group, entity_identifier=entity_identifier, action=u'set')

        if successful_entities:
            output_message = u"Successfully removed the following IP addresses from the shared address group " \
                             u"'{}' in Palo Alto NGFW: {} \n".format(group, u', '.join(successful_entities))
        else:
            output_message = u"No IP addresses were removed from the shared address group '{}' " \
                             u"in Palo Alto NGFW.\n".format(group)
            result_value = False

        if not_existing_entities:
            result_value = True
            output_message += u"The following IP addresses were not a part of the shared address group '{}' " \
                              u"in Palo Alto NGFW: {}\n".format(group, u', '.join(not_existing_entities))

        json_results["success"] = successful_entities
        json_results["didn't_exist_initially"] = not_existing_entities
        siemplify.result.add_result_json(json.dumps(json_results))

    except Exception as e:
        output_message = u'Error executing action "Remove Ips from group". Reason: {}'.format(e)
        if isinstance(e, GroupNotExistsException):
            output_message += u'Shared address group "{}" was not found in Palo Alto NGFW'.format(group)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
