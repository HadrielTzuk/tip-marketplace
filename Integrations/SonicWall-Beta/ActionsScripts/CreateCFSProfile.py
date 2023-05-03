from SiemplifyAction import SiemplifyAction
from SonicWallManager import SonicWallManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import (
    INTEGRATION_NAME,
    CREATE_CFS_SCRIPT_NAME
)

from SonicWallExceptions import (
    UnableToAddException,
    UnauthorizedException
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_CFS_SCRIPT_NAME
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
    profile_name = extract_action_param(siemplify, param_name=u'Name', is_mandatory=True)
    allowed_uri = extract_action_param(siemplify, param_name=u'Allowed URI List or Group', is_mandatory=False)
    forbidden_uri = extract_action_param(siemplify, param_name=u'Forbidden URI List or Group', is_mandatory=False)
    search_order = extract_action_param(siemplify, param_name=u'Search Order', default_value=u'Allowed URI First',
                                        is_mandatory=True)
    forbidden_operation = extract_action_param(siemplify, param_name=u'Operation for Forbidden URI',
                                               default_value=u'Block', is_mandatory=True)
    smart_filter = extract_action_param(siemplify, param_name=u'Enable Smart Filter', default_value=True,
                                        input_type=bool, is_mandatory=True)
    google_search = extract_action_param(siemplify, param_name=u'Enable Google Safe Search', default_value=True,
                                         input_type=bool, is_mandatory=True)
    youtube_mode = extract_action_param(siemplify, param_name=u'Enable Youtube Restricted Mode', default_value=True,
                                        input_type=bool, is_mandatory=True)
    bing_search = extract_action_param(siemplify, param_name=u'Enable Bing Safe Search', default_value=True,
                                       input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = u'false'

    try:
        sonic_wall_manager = SonicWallManager(api_root, username, password, verify_ssl=verify_ssl,
                                              siemplify_logger=siemplify.LOGGER)
        sonic_wall_manager.create_cfs_profile(profile_name=profile_name, allowed=allowed_uri, forbidden=forbidden_uri,
                                              search_order=search_order, forbidden_operation=forbidden_operation,
                                              smart_filter=smart_filter, safe_search=google_search,
                                              youtube_mode=youtube_mode, bing_search=bing_search)
        sonic_wall_manager.confirm_changes()
        output_message = u'Successfully created SonicWall CFS Profile \"{}\"'.format(profile_name)
        result_value = u'true'

    except UnableToAddException as e:
        reason_message = unicode(e.args[0].message)
        command_message = unicode(e.args[0].command)
        output_message = u"CFS Profile \"{}\" was not created in SonicWall:\nReason: {} \nCommand: {}".format(
            profile_name, reason_message, command_message)

    except UnauthorizedException as e:
        output_message = unicode(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    except Exception as e:
        output_message = u"Error executing action \"Create CFS Profile\". Reason: {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(u'----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        u"\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
