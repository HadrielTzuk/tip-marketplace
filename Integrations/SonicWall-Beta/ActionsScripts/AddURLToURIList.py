from SiemplifyAction import SiemplifyAction
from SonicWallManager import SonicWallManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from SiemplifyDataModel import EntityTypes
from constants import (
    INTEGRATION_NAME,
    ADD_URL_SCRIPT_NAME,
    NOT_FOUND_ERROR_CODE
)

from SonicWallExceptions import (
    UnableToAddException,
    UnauthorizedException
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_URL_SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # Configuration.
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           input_type=unicode, is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           input_type=unicode, is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                           input_type=unicode, is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    # Parameters
    uri_list = extract_action_param(siemplify, param_name=u'URI List Name', is_mandatory=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = u'true'
    output_message = u''
    successful_entities = []
    failed_entities = []
    uri_list_exists = True

    try:
        sonic_wall_manager = SonicWallManager(api_root, username, password, verify_ssl=verify_ssl,
                                              siemplify_logger=siemplify.LOGGER)
        url_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.URL]
        for entity in url_entities:
            siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
            try:
                sonic_wall_manager.add_url_to_uri_list(uri_list, entity.identifier)
                sonic_wall_manager.confirm_changes()
                successful_entities.append(entity)
            except UnableToAddException as e:
                reason_message = unicode(e.args[0].message)
                command_message = unicode(e.args[0].command)
                error_code = unicode(e.args[0].code)
                if error_code == NOT_FOUND_ERROR_CODE:
                    uri_list_exists = False
                    break
                else:
                    failed_entities.append({u'entity': entity, u'reason': reason_message, u'command': command_message})

            siemplify.LOGGER.info(u"Finished processing entity: {}".format(entity.identifier))

        if successful_entities:
            output_message = u'Successfully added the following URLs to the SonicWall URI List \"{}\": {}'.format(
                uri_list, u'\n'.join([entity.identifier for entity in successful_entities]))

        if failed_entities:
            for item in failed_entities:
                output_message += u'\n\nAction was not able to add the following URL to the SonicWall URI List \"{}\"' \
                                  u': {}. \nReason: {}. Command: {}.'.format(uri_list, item.get(u"entity"),
                                                                             item.get(u'reason'), item.get(u'command'))

        if not successful_entities:
            output_message = u''
            for item in failed_entities:
                output_message += u'\nURL was not added to the SonicWall URI List \"{}\"' \
                                  u': {}. \nReason: {}. Command: {}.'.format(uri_list, item.get(u"entity"),
                                                                             item.get(u'reason'), item.get(u'command'))
            result_value = u'false'

        if not url_entities:
            output_message = u'No suitable entities found'
            result_value = u'false'

        if not uri_list_exists:
            output_message = u"URI List \"{}\" wasn't found in SonicWall".format(uri_list)
            result_value = u'false'

    except UnauthorizedException as e:
        output_message = unicode(e)
        result_value = u'false'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    except Exception as e:
        output_message = u"Error executing action \"Add URL to URI List\". Reason: {}".format(e)
        result_value = u'false'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(u'----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        u"\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
