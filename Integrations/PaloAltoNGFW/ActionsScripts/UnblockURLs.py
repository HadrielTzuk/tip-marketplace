from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from NGFWManager import NGFWManager, CategoryNotExistsException
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED


INTEGRATION_NAME = u"PaloAltoNGFW"
SUPPORTED_ENTITY_TYPES = [EntityTypes.URL]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"NGFW - UnblockURLs"
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
    policy_name = extract_action_param(siemplify, param_name=u"URL Category Name", print_value=True)
    use_shared_objects = extract_action_param(siemplify, param_name=u"Use Shared Objects", print_value=True,
                                              input_type=bool)

    output_message = u''
    status = EXECUTION_STATE_COMPLETED
    successful_entities, not_existing_entities = [], []
    json_results = {"success": [], "didn't_exist_initially": []}
    result_value = True
    suitable_entity_identifiers = [entity.identifier for entity in siemplify.target_entities
                                   if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        if not use_shared_objects and (not device_name or not vsys_name):
            raise Exception(u'Either "Use Shared Objects" parameter should be enabled or "Device name" '
                            'and "Vsys name" to be provided.')

        api = NGFWManager(api_root, username, password, siemplify.run_folder, siemplify.LOGGER, verify_ssl=verify_ssl)

        if not use_shared_objects:
            current_urls = api.FindRuleBlockedUrls(device_name, vsys_name, policy_name)
            if current_urls is not None: 
                existing_urls = list(current_urls)
            else:
                existing_urls = []
            for entity_identifier in suitable_entity_identifiers:
                if entity_identifier not in existing_urls:
                    not_existing_entities.append(entity_identifier)
                else:
                    api.EditBlockedUrls(deviceName=device_name, vsysName=vsys_name, policyName=policy_name,
                                        urlsToRemove=[entity_identifier])
                    successful_entities.append(entity_identifier)
        else:
            urls_from_category = api.ListSharedUrlsFromCategory(category_name=policy_name)
            not_existing_entities = [url for url in suitable_entity_identifiers if url not in urls_from_category]
            stay_urls = [url for url in urls_from_category if url not in suitable_entity_identifiers]
            removable_entities = [url for url in urls_from_category if url in suitable_entity_identifiers]

            for entity_identifier in removable_entities:
                api.EditSharedUrlInCategory(category_name=policy_name, entity_identifier=entity_identifier,
                                            action=u'delete')
                successful_entities.append(entity_identifier)

            for entity_identifier in stay_urls:
                api.EditSharedUrlInCategory(category_name=policy_name, entity_identifier=entity_identifier,
                                            action=u'set')

        if successful_entities:
            output_message = u"Successfully removed the following URLs from the shared category '{}' in " \
                             u"Palo Alto NGFW: {} \n".format(policy_name, u', '.join(successful_entities))
        else:
            output_message = u"No URLs were removed from the shared category '{}' in Palo Alto NGFW.\n" \
                .format(policy_name)
            result_value = False

        if not_existing_entities:
            result_value = True
            output_message += u"The following URLs were not a part of the the shared category '{}' " \
                              u"in Palo Alto NGFW: {}\n".format(policy_name, u', '.join(not_existing_entities))

        json_results["success"] = successful_entities
        json_results["didn't_exist_initially"] = not_existing_entities
        siemplify.result.add_result_json(json_results)

    except Exception as e:
        output_message = u'Error executing action "Unblock URLs". Reason: {}'.format(e)
        if isinstance(e, CategoryNotExistsException):
            output_message += u'Shared category "{}" was not found in Palo Alto NGFW.'.format(policy_name)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
