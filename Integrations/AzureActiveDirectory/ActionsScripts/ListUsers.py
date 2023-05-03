from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from AzureADManager import AzureADManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import construct_csv, extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, LIST_USERS_SCRIPT_NAME, LIST_USERS_TABLE_NAMES, USERS_LIST_PRIORITY_FILDS
from exceptions import AzureWrongFiltersError

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_USERS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client ID',
                                            is_mandatory=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client Secret',
                                                is_mandatory=True)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Directory ID',
                                         is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    order_by = extract_action_param(siemplify, param_name="Order By", print_value=True, default_value="ASC")

    filter_fields = extract_action_param(siemplify, param_name="Filter", print_value=True, default_value="All Fields")

    order_by_field = extract_action_param(siemplify, param_name="Order By Field", print_value=True,
                                          default_value="displayName")

    limit = extract_action_param(siemplify, param_name="Results Limit", input_type=int, print_value=True)

    filter_logic = extract_action_param(siemplify, param_name="Advanced Filter Logic", print_value=True,
                                        default_value="Equal")

    filter_value = extract_action_param(siemplify, param_name="Advanced Filter Value", print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    list_of_users_csv, json_result = [], []
    output_message = "List of users fetched successfully."
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    try:
        manager = AzureADManager(client_id=client_id, client_secret=client_secret, tenant=tenant, verify_ssl=verify_ssl,
                                 force_check_connectivity=True)

        if filter_value and filter_fields not in USERS_LIST_PRIORITY_FILDS:
            raise AzureWrongFiltersError("Failed to run the action.")
        list_of_users = manager.get_list_of_users(filter_field=filter_fields, filter_value=filter_value,
                                                  filter_logic=filter_logic, order_by=order_by,
                                                  order_by_field=order_by_field, limit=limit)
        if not list_of_users:
            output_message = "No users were returned based on provided filter criteria"
            result_value = False
        list_of_users_csv = [user.to_csv(filter_fields) for user in list_of_users]
        json_result = [user.to_json() for user in list_of_users]
        if list_of_users_csv:
            siemplify.result.add_data_table(LIST_USERS_TABLE_NAMES, data_table=construct_csv(list_of_users_csv))

    except AzureWrongFiltersError as e:
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = "Failed to run the action with advanced filtering because username field was filtered out"
    except Exception as e:
        siemplify.LOGGER.error(f"Some errors occurred. Error: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Some errors occurred. Please check log. Error: {e}"
    if json_result:
        siemplify.result.add_result_json(json_result)
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()