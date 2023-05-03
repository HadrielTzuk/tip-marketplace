from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from PanoramaManager import PanoramaManager
from TIPCommon import extract_configuration_param, extract_action_param
import json

SCRIPT_NAME = u"Panorama - BlockURLs"
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
    category = extract_action_param(siemplify, param_name=u"URL Category Name", is_mandatory=True, print_value=True)

    urlToBlock = []
    json_results = []
    result_value = u'true'
    output_message = u""
    successful_entities = []
    failed_entities = []

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    for entity in siemplify.target_entities:
        if entity.entity_type == EntityTypes.URL:
            urlToBlock.append(entity.identifier.replace("&amp;", "&").replace("&", "&amp;"))

    if urlToBlock:
        api = PanoramaManager(server_address, username, password, verify_ssl, siemplify.run_folder)
        for url in urlToBlock:
            siemplify.LOGGER.info(u"Process entity: {} Started".format(url))
            try:
                siemplify.LOGGER.info(u"Adding url {} to blacklist".format(url))
                api.AddBlockedUrls(device_name=deviceName, device_group_name=device_group_name, policy_name=category, urls_to_add=[url])
                siemplify.LOGGER.info(u"Successfully blacklisted url {}".format(url))
                successful_entities.append(url)
            except Exception as error:
                siemplify.LOGGER.error(u'Failed to block url {}'.format(url))
                siemplify.LOGGER.exception(error)
                failed_entities.append(url)

        json_results = api.FindRuleBlockedUrls(deviceName, device_group_name, category)

        if successful_entities:
            output_message += (u'Successfully added the following URLs to the Palo Alto Panorama URL Category \"{}\": '
                               u'{}'.format(category, u"\n".join([entity for entity in successful_entities])))

        if failed_entities:
            output_message += u"\n\nAction was not able to add the following URLs to the Palo Alto Panorama URL " \
                              u"Category \"{}\": {}".format(category, u"\n".join([entity for entity in
                                                                                  failed_entities]))

        if not successful_entities:
            output_message = u"No URLs were added to the Palo Alto Panorama URL Category \"{}\"".format(category)
            result_value = u'false'

    else:
        output_message = u"No URLs found"
        siemplify.LOGGER.info(output_message)
        result_value = u'false'

    siemplify.result.add_result_json(json.dumps(list(json_results)))
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
