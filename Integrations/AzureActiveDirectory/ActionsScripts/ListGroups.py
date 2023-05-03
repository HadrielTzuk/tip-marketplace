from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from AzureADManager import AzureADManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import construct_csv, extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, LIST_GROUPS_SCRIPT_NAME, LIST_GROUPS_TABLE_NAMES

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_GROUPS_SCRIPT_NAME
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

    limit = extract_action_param(siemplify, param_name="Results Limit", input_type=int, print_value=True)

    filter_logic = extract_action_param(siemplify, param_name="Filter Logic", print_value=True, default_value="Equal")

    filter_value = extract_action_param(siemplify, param_name="Filter Value", print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    list_of_groups_csv = []
    output_message = "List of groups fetched successfully."
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    try:

        manager = AzureADManager(client_id=client_id, client_secret=client_secret, tenant=tenant, verify_ssl=verify_ssl,
                                 force_check_connectivity=True)
        list_of_groups = manager.get_list_of_groups(filter_value=filter_value, filter_logic=filter_logic,
                                                    order_by=order_by, limit=limit)
        if not list_of_groups:
            output_message = "No groups were returned based on provided filter criteria"
            result_value = False
        list_of_groups_csv = [group.to_csv() for group in list_of_groups if group.to_csv()]
        if list_of_groups_csv:
            siemplify.result.add_data_table(title=LIST_GROUPS_TABLE_NAMES, data_table=construct_csv(list_of_groups_csv))


    except Exception as e:
        siemplify.LOGGER.error(f"Some errors occurred. Error: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Some errors occurred. Please check log. Error: {e}"
    if list_of_groups_csv:
        siemplify.result.add_result_json(list_of_groups_csv)
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()