from SiemplifyAction import SiemplifyAction
from SonicWallManager import SonicWallManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, dict_to_flat, construct_csv
from constants import (
    INTEGRATION_NAME,
    LIST_ADDRESS_GROUPS_SCRIPT_NAME,
    IPV4_TYPE_STRING,
    IPV6_TYPE_STRING,
    ALL_TYPE_STRING,
    MAX_LIMIT
)
from SonicWallExceptions import (
    UnauthorizedException
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_ADDRESS_GROUPS_SCRIPT_NAME
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
    address_type = extract_action_param(siemplify, param_name=u'Address Type', is_mandatory=False)
    groups_limit = extract_action_param(siemplify, param_name=u'Max Address Groups To Return', default_value=MAX_LIMIT,
                                        input_type=int, is_mandatory=False)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = u'true'
    json_results = []
    
    if groups_limit <= 0:
        groups_limit = MAX_LIMIT

    try:
        sonic_wall_manager = SonicWallManager(api_root, username, password, verify_ssl=verify_ssl,
                                              siemplify_logger=siemplify.LOGGER)
        if address_type.lower() == ALL_TYPE_STRING:
            ipv4_groups = sonic_wall_manager.get_address_groups(IPV4_TYPE_STRING)
            ipv6_groups = sonic_wall_manager.get_address_groups(IPV6_TYPE_STRING)
            output_message, json_results = create_siemplify_results(siemplify, ipv4_groups, groups_limit,
                                                                    IPV4_TYPE_STRING, json_results)
            message, json_results = create_siemplify_results(siemplify, ipv6_groups, groups_limit, IPV6_TYPE_STRING,
                                                             json_results)
            output_message += u'\n\n{}'.format(message)
            siemplify.result.add_result_json(json_results)
        elif address_type.lower() == IPV4_TYPE_STRING:
            ipv4_groups = sonic_wall_manager.get_address_groups(IPV4_TYPE_STRING)
            output_message, json_results = create_siemplify_results(siemplify, ipv4_groups, groups_limit,
                                                                    IPV4_TYPE_STRING, json_results)
            siemplify.result.add_result_json(json_results)
        else:
            ipv6_groups = sonic_wall_manager.get_address_groups(IPV6_TYPE_STRING)
            output_message, json_results = create_siemplify_results(siemplify, ipv6_groups, groups_limit,
                                                                    IPV6_TYPE_STRING, json_results)
            siemplify.result.add_result_json(json_results)

    except UnauthorizedException as e:
        output_message = unicode(e)
        result_value = u'false'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    except Exception as e:
        output_message = u"Error executing action \"List Address Groups\". Reason: {}".format(e)
        result_value = u'false'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(u'----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        u"\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


def create_siemplify_results(siemplify, address_groups, groups_limit, address_type, json_results):
    if address_groups:
        address_groups = address_groups[:groups_limit]
        table_results = []

        for group in address_groups:
            table_results.append(group.to_row_data())
            json_results.append(group.to_json())

        flat_results = map(dict_to_flat, table_results)
        csv_output = construct_csv(flat_results)
        table_name = u'Available {} Address Groups'.format(address_type)
        siemplify.result.add_data_table(table_name, csv_output)
        return u'Successfully listed SonicWall {} address groups!'.format(address_type), json_results
    else:
        return u'No SonicWall {} address groups were found!'.format(address_type), json_results


if __name__ == '__main__':
    main()
