from SiemplifyUtils import output_handler
from ZscalerManager import ZscalerManager
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from SiemplifyDataModel import EntityTypes
from TIPCommon import flat_dict_to_csv, dict_to_flat, extract_configuration_param
from SiemplifyUtils import create_entity_json_result_object


INTEGRATION_NAME = u"Zscaler"
ACTION_NAME = u"Lookup URL"


def match_entity(zscaler_manager, entities, entity_name):
    for entity in entities:
        if zscaler_manager.validate_and_extract_url(entity.identifier.lower()) == entity_name:
            return entity

    raise Exception(u"No matching entity was found for {}".format(entity_name))


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, ACTION_NAME)
    siemplify.LOGGER.info(u'----------------- Main - Param Init -----------------')

    cloud_name = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u'Api Root',
                                             is_mandatory=True)
    login_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u'Login ID',
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u'Api Key',
                                          is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u'Password',
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u'Verify SSL',
                                             is_mandatory=True, default_value=True, input_type=bool)

    siemplify.LOGGER.info(u'----------------- Main - Started -----------------')

    urls = []
    errors = []
    json_results = []
    output_message = u''
    result_value = u'false'
    status = EXECUTION_STATE_COMPLETED

    entities_to_look_for = []
    urls_to_look_for = []

    try:
        zscaler_manager = ZscalerManager(cloud_name, login_id, api_key, password, verify_ssl=verify_ssl, logger=siemplify.LOGGER)

        for entity in siemplify.target_entities:
            if entity.entity_type == EntityTypes.URL or entity.entity_type == EntityTypes.HOSTNAME:
                entities_to_look_for.append(entity)
                siemplify.LOGGER.info(u"Adding {} to urls list to look for.".format(
                    zscaler_manager.validate_and_extract_url(entity.identifier.lower())
                ))
                urls_to_look_for.append(zscaler_manager.validate_and_extract_url(entity.identifier.lower()))

        siemplify.LOGGER.info(u"Looking for the URLs in Zscaler.")
        urls_info = zscaler_manager.lookup_urls(urls_to_look_for)

        if urls_info:
            for url_info in urls_info:
                entity_name = url_info.get(u'url')
                siemplify.LOGGER.info(u"Found info for {}".format(entity_name))
                try:
                    entity = match_entity(zscaler_manager, entities_to_look_for, url_info.get(u'url'))
                    urls.append(entity.identifier)
                    result_value = u'true'
                    json_results.append(create_entity_json_result_object(entity.identifier, url_info))
                    flat_info = dict_to_flat(url_info)
                    siemplify.result.add_entity_table(u'{} Categorization'.format(entity.identifier),
                                                      flat_dict_to_csv(flat_info))
                except Exception as e:
                    # An error occurred - skip entity and continue
                    siemplify.LOGGER.error(u"An error occurred on entity: {}.\n{}.".format(entity_name, unicode(e)))
                    siemplify.LOGGER.exception(e)
                    errors.append(entity_name)

        if urls:
            output_message += u'The following entities found in Zscaler: \n{}'.format(u'\n'.join(urls))
            result_value = u'true'

        if errors:
            output_message += u'Errors occurred on the following entities: \n{}\nCheck logs for more details'.format(u'\n'.join(errors))

        if not urls and not errors:
            output_message = u'No entities were found in Zscaler.'

    except Exception as e:
        siemplify.LOGGER.error(u"An error occurred while executing action: {}".format(e))
        siemplify.LOGGER.exception(e)
        output_message = u"An error occurred while executing action: {}".format(e)
        result_value = u"false"
        status = EXECUTION_STATE_FAILED

    # add json
    siemplify.result.add_result_json(json_results)
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u'Status: {}'.format(status))
    siemplify.LOGGER.info(u'Result: {}'.format(result_value))
    siemplify.LOGGER.info(u'Output Message: {}'.format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == u'__main__':
    main()
