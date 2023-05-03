from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from NGFWManager import NGFWManager, GroupNotExistsException, AlreadyExistsException
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

INTEGRATION_NAME = u"PaloAltoNGFW"
SUPPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"NGFW - AddIpsToGroup"

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Root",
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           print_value=False)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                           print_value=False)

    device_name = extract_action_param(siemplify, param_name=u"Device Name", print_value=True)
    vsys_name = extract_action_param(siemplify, param_name=u"Vsys Name", print_value=True)
    group_name = extract_action_param(siemplify, param_name=u"Address Group Name", print_value=True, is_mandatory=True)
    use_shared_objects = extract_action_param(siemplify, param_name=u"Use Shared Objects", print_value=True,
                                              input_type=bool)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)

    output_message = u''
    status = EXECUTION_STATE_COMPLETED
    successful_entities, failed_entities, existing_entities = [], [], []
    json_results = {"success": [], "failure": [], "already_exist": []}
    result_value = True
    suitable_entity_identifiers = [entity.identifier for entity in siemplify.target_entities
                                   if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        if not use_shared_objects and (not device_name or not vsys_name):
            raise Exception(u'Either "Use Shared Objects" parameter should be enabled or "Device name" '
                            'and "Vsys name" to be provided.')

        api = NGFWManager(api_root, username, password, siemplify.run_folder, siemplify.LOGGER, verify_ssl=verify_ssl)

        if not use_shared_objects:
            existing_addresses = list(
                api.ListAddressesInGroup(deviceName=device_name, vsysName=vsys_name, groupName=group_name) or set()
            ) or []
            for entity_identifier in suitable_entity_identifiers:
                if entity_identifier in existing_addresses:
                    existing_entities.append(entity_identifier)
                else:
                    try:
                        api.EditBlockedIpsInGroup(deviceName=device_name, vsysName=vsys_name, groupName=group_name,
                                                  IpsToAdd=[entity_identifier])
                        successful_entities.append(entity_identifier)
                    except Exception as err:
                        siemplify.LOGGER.error(u"Some errors occurred '{}'".format(err))
                        siemplify.LOGGER.exception(err)
                        failed_entities.append(entity_identifier)
        else:
            for entity_identifier in suitable_entity_identifiers:
                try:
                    api.EnitityExistsInGroup(group_name=group_name, entity_identifier=entity_identifier)
                    if not api.IsEntityShared(entity_identifier=entity_identifier):
                        api.AddSharedEntity(entity_identifier)

                    api.EditSharedIpsInGroup(group_name=group_name, entity_identifier=entity_identifier, action=u'set')

                    successful_entities.append(entity_identifier)
                except GroupNotExistsException as err:
                    siemplify.LOGGER.error(u"Group wasn't found '{}'".format(group_name))
                    siemplify.LOGGER.exception(err)
                    raise Exception(u'Shared address group "{}" was not found in Palo Alto NGFW'.format(group_name))
                except AlreadyExistsException as err:
                    siemplify.LOGGER.error("Entity already a part of group '{}'".format(entity_identifier))
                    siemplify.LOGGER.exception(err)
                    existing_entities.append(entity_identifier)
                except Exception as err:
                    siemplify.LOGGER.error(u"Some errors occurred '{}'".format(err))
                    siemplify.LOGGER.exception(err)
                    failed_entities.append(entity_identifier)

        if successful_entities:
            output_message = u"Successfully added the following IP addresses to the shared address group '{}' in" \
                             " Palo Alto NGFW: {} \n".format(group_name, u', '.join(successful_entities))

            if failed_entities:
                output_message += u"Action wasn't able to add the following IP addresses to the shared address " \
                                  "group '{}' in Palo Alto NGFW: {}\n".format(group_name, u', '.join(failed_entities))
        else:
            output_message = u"No IP addresses were added to the shared address group '{}' in Palo Alto NGFW.\n" \
                .format(group_name)
            result_value = False

        if existing_entities:
            result_value = True
            output_message += u"The following IP addresses were already a part of the the shared address " \
                              "group '{}' in Palo Alto NGFW: {}\n".format(group_name, u', '.join(existing_entities))

        json_results['success'] = successful_entities
        json_results['failure'] = failed_entities
        json_results['already_exist'] = existing_entities
        siemplify.result.add_result_json(json_results)

    except Exception as e:
        output_message = u'Error executing action "Add Ips to group". Reason: {}'.format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
