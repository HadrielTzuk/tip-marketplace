from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from utils import string_to_multi_value
from constants import (
    INTEGRATION_NAME,
    GET_GROUP_DETAILS_SCRIPT_NAME,
    SENTINEL_ONE_GROUPS_TABLE_NAME,
    PRODUCT_NAME,
)
from SentinelOneV2Factory import SentinelOneV2ManagerFactory


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_GROUP_DETAILS_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    group_names = string_to_multi_value(extract_action_param(siemplify, param_name="Group Names", is_mandatory=True,
                                                             print_value=True))

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    successful_groups, failed_group_names, json_results = [], [], {}

    try:
        manager = SentinelOneV2ManagerFactory().get_manager(api_root=api_root, api_token=api_token,
                                                            verify_ssl=verify_ssl)

        for group_name in group_names:
            try:
                siemplify.LOGGER.info('Getting group details for: {}'.format(group_name))
                group = manager.get_group_details(group_name=group_name)
                siemplify.LOGGER.info('Successfully got {} group details'.format(group_name))
                if group and group.id:  # to validate response, id must present in group details
                    successful_groups.append(group)
                    json_results[group_name] = group.to_json()
                else:
                    failed_group_names.append(group_name)

            except Exception as e:
                siemplify.LOGGER.exception(e)
                failed_group_names.append(group_name)

        if successful_groups:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            siemplify.result.add_data_table(SENTINEL_ONE_GROUPS_TABLE_NAME,
                                            construct_csv([group.as_csv() for group in successful_groups]))
            output_message = 'Successfully retrieved information about the following groups in {}:\n   {}\n'\
                .format(PRODUCT_NAME, '\n   '.join([group.name for group in successful_groups]))
            if failed_group_names:
                output_message += "Action wasn't able to retrieve information about the following groups in {}:\n   {}"\
                    .format(PRODUCT_NAME, '\n   '.join(failed_group_names))
        else:
            result_value = False
            output_message = 'No information about the provided groups was found'

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(GET_GROUP_DETAILS_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
