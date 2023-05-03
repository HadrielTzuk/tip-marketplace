from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from CiscoISEManager import CiscoISEManager
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyDataModel import EntityTypes


INTEGRATION_NAME = u"CiscoISE"
PRODUCT_NAME = u"Cisco ISE"
SCRIPT_NAME = u"Cisco ISE - Add Endpoint To Endpoint Identity Group"

# Fix misalignment of MAC entity type
EntityTypes.MACADDRESS = EntityTypes.MACADDRESS.upper()
SUPPORTED_ENTITY_TYPES = [EntityTypes.MACADDRESS, EntityTypes.ADDRESS]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           print_value=True, is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           print_value=True, is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             input_type=bool, print_value=True, is_mandatory=True)

    # Action parameters
    endpoint_group_name = extract_action_param(siemplify, param_name=u"Endpoint Identity Group Name",
                                               print_value=True, is_mandatory=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED
    successful_entities, failed_entities, json_results = [], [], {}
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        manager = CiscoISEManager(api_root=api_root, username=username, password=password, verify_requests=verify_ssl,
                                  logger=siemplify.LOGGER)

        groups = manager.get_endpoint_groups("name", "EQ", endpoint_group_name, 100)

        if groups:
            group_id = groups[0].id
            for entity in suitable_entities:
                siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
                try:
                    mac_address = manager.get_endpoint_mac_by_ip(entity.identifier) if \
                        entity.entity_type == EntityTypes.ADDRESS else entity.identifier
                    endpoint_id = next((endpoint.get("id") for endpoint in manager.get_endpoints()
                                        if endpoint.get("name", "") == mac_address), None)
                    if endpoint_id:
                        json_response = manager.add_endpoint_to_group(endpoint_id, group_id)
                        successful_entities.append(entity)
                        json_results[entity.identifier] = json_response
                    else:
                        failed_entities.append(entity)
                except Exception as e:
                    failed_entities.append(entity.identifier)
                    siemplify.LOGGER.error(u"An error occurred on entity {}".format(entity.identifier))
                    siemplify.LOGGER.exception(e)

                siemplify.LOGGER.info(u"Finished processing entity: {}".format(entity.identifier))
        else:
            raise Exception(u"Endpoint Identity Group \'{}\' wasn't found in Cisco ISE. "
                            u"Please check the spelling.".format(endpoint_group_name))

        if successful_entities:
            output_message = u'Successfully added the following endpoints to the \"{}\" Endpoint ' \
                             u'Identity Group in {}: {}\n\n'.format(endpoint_group_name,
                                                                    PRODUCT_NAME,
                                                                    ", ".join([entity.identifier
                                                                               for entity in successful_entities]))
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

            if failed_entities:
                output_message += u'Action wasn\'t able to find the following endpoints in {}: {}\n'.format(
                    PRODUCT_NAME, ", ".join(failed_entities))
        else:
            output_message = u"None of the provided endpoints were found."
            result = False

    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = u"Error executing action \"{}\". Reason: {}".format(SCRIPT_NAME, e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
