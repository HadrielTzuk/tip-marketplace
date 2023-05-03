from SiemplifyAction import SiemplifyAction
from SonicWallManager import SonicWallManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import (
    INTEGRATION_NAME,
    ADD_URI_TO_GROUP_SCRIPT_NAME,
    NOT_FOUND_ERROR_CODE
)

from SonicWallExceptions import (
    UnableToAddException,
    UnauthorizedException
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_URI_TO_GROUP_SCRIPT_NAME
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
    uri_group = extract_action_param(siemplify, param_name=u'URI Group Name', is_mandatory=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = u'false'

    try:
        sonic_wall_manager = SonicWallManager(api_root, username, password, verify_ssl=verify_ssl,
                                              siemplify_logger=siemplify.LOGGER)
        sonic_wall_manager.add_uri_list_to_uri_group(uri_list, uri_group)
        sonic_wall_manager.confirm_changes()
        output_message = u'Successfully added the URI List \"{}\" to the SonicWall URI Group \"{}\"'.format(uri_list,
                                                                                                            uri_group)
        result_value = u'true'

    except UnableToAddException as e:
        reason_message = unicode(e.args[0].message)
        command_message = unicode(e.args[0].command)
        error_code = unicode(e.args[0].code)
        if error_code == NOT_FOUND_ERROR_CODE:
            output_message = u"URI Group \"{}\" wasn't found in SonicWall".format(uri_group)
        else:
            output_message = u"URI List \"{}\" was not added to the SonicWall URI Group \"{}\":\nReason: " \
                             u"{} \nCommand: {}".format(uri_list, uri_group, reason_message, command_message)

    except UnauthorizedException as e:
        output_message = unicode(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    except Exception as e:
        output_message = u"Error executing action \"Add URI List to URI Group\". Reason: {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(u'----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        u"\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
