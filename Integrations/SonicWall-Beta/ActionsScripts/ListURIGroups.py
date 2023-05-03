from SiemplifyAction import SiemplifyAction
from SonicWallManager import SonicWallManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, dict_to_flat, construct_csv
from constants import (
    INTEGRATION_NAME,
    LIST_URI_GROUPS_SCRIPT_NAME,
    MAX_LIMIT
)
from SonicWallExceptions import (
    UnauthorizedException
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_URI_GROUPS_SCRIPT_NAME
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
    groups_limit = extract_action_param(siemplify, param_name=u'Max URI Groups To Return', default_value=MAX_LIMIT,
                                        input_type=int, is_mandatory=False)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = u'false'

    if groups_limit <= 0:
        groups_limit = MAX_LIMIT
        
    try:
        sonic_wall_manager = SonicWallManager(api_root, username, password, verify_ssl=verify_ssl,
                                              siemplify_logger=siemplify.LOGGER)
        results = sonic_wall_manager.get_groups()     
        if results:
            results = results[:groups_limit]
            table_results = []
            json_results = []

            for uri_list_object in results:
                raw_data = {u'Name': uri_list_object.name, u'URI List Count': len(uri_list_object.uri_list), u'URI Group Count': len(uri_list_object.uri_group)}
                table_results.append(raw_data)
                json_results.append(uri_list_object.to_json()) 

            flat_results = map(dict_to_flat, table_results)
            csv_output = construct_csv(flat_results)
            siemplify.result.add_data_table(u'Available URI Groups', csv_output)
            siemplify.result.add_result_json(json_results)  
            
            output_message = u'Successfully listed SonicWall URI Groups!'
            result_value = u'true'
        else:
            output_message = u'No SonicWall URI Groups were found!'

    except UnauthorizedException as e:
        output_message = unicode(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    except Exception as e:
        output_message = u"Error executing action \"List URI Groups\". Reason: {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(u'----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        u"\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
