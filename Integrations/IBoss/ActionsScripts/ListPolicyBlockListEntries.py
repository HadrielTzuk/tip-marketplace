from SiemplifyAction import SiemplifyAction
from IBossManager import IBossManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import LIST_POLICY_BLOCK_LIST_ENTRIES_SCRIPT_NAME, INTEGRATION_NAME
from exceptions import ListIsNotBlockListException

CSV_CASE_WALL_NAME = 'Block List Entries. Category {}'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_POLICY_BLOCK_LIST_ENTRIES_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    cloud_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Cloud API Root',
                                           is_mandatory=True)
    account_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Account API Root',
                                           is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Username',
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Password',
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=True, input_type=bool)

    category_id = extract_action_param(siemplify, param_name='Category ID', is_mandatory=True, print_value=True)
    max_entries_to_return = extract_action_param(siemplify, param_name='Max Entries to Return', is_mandatory=True,
                                                 input_type=int, print_value=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_FAILED
    result_value = False
    try:
        manager = IBossManager(cloud_api_root, account_api_root, username, password, verify_ssl, siemplify.LOGGER)
        manager.validate_if_block_list(category_id)
        entries = manager.list_policy_block_list_entries(category_id, max_entries_to_return)
        if entries:
            siemplify.result.add_result_json([entry.to_json() for entry in entries])
            siemplify.result.add_data_table(title=CSV_CASE_WALL_NAME.format(category_id),
                                            data_table=construct_csv([entry.to_csv() for entry in entries]))

            result_value = True
            output_message = 'Successfully listed entries from the iBoss Block List in a category with ID \'{0}\''.format(
                category_id)
        else:
            output_message = 'No Block List entries were found in the iBoss category with ID \'{0}\''.format(
                category_id)
        siemplify.LOGGER.info(output_message)

        status = EXECUTION_STATE_COMPLETED
    except ListIsNotBlockListException:
        output_message = "Category with ID {} is not associated with a Block list.".format(category_id)
        siemplify.LOGGER.info(output_message)
        status = EXECUTION_STATE_COMPLETED
    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(LIST_POLICY_BLOCK_LIST_ENTRIES_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
