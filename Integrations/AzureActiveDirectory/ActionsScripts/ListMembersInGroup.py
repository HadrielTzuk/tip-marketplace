from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from AzureADManager import AzureADManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import construct_csv, extract_configuration_param, extract_action_param, construct_csv
from constants import FILTER_LOGIC_CONTAINS, FILTER_LOGIC_EQUALS, SELECT_ONE_FILTER_KEY, INTEGRATION_NAME, LIST_MEMBERS_IN_GROUP_SCRIPT_NAME, LIST_GROUPS_TABLE_NAMES, INTEGRATION_DISPLAY_NAME

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_MEMBERS_IN_GROUP_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client ID',
                                            is_mandatory=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client Secret',
                                                is_mandatory=True)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Directory ID',
                                         is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)


    limit = extract_action_param(siemplify, param_name="Max Records To Return", default_value=50, input_type=int, print_value=True)

    group_name = extract_action_param(siemplify, param_name="Group Name", print_value=True, is_mandatory=False)

    group_id_param = extract_action_param(siemplify, param_name='Group ID', print_value=True, is_mandatory=False)

    filter_logic = extract_action_param(siemplify, param_name="Filter Logic", print_value=True)
    
    filter_key = extract_action_param(siemplify, param_name="Filter Key", print_value=True)

    filter_value = extract_action_param(siemplify, param_name="Filter Value", print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    list_of_groups_csv = []
    output_message = ""
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    group_id = group_id_param

    try:
        if not group_name and not group_id_param:
            raise Exception(f"Either \"Group ID\" or \"Group Name\" needs to be provided.")

        if limit < 1:
             raise Exception(f"Invalid value was provided for \"Max Records to Return\": {limit}. Positive number should be provided.")

        if filter_key == SELECT_ONE_FILTER_KEY and (filter_logic == FILTER_LOGIC_EQUALS or filter_logic == FILTER_LOGIC_CONTAINS):
            raise Exception(f"you need to select a field from the \"Filter Key\" parameter.")
        
        manager = AzureADManager(client_id=client_id, client_secret=client_secret, tenant=tenant, verify_ssl=verify_ssl,
                                 force_check_connectivity=True)
        if not group_id_param:
            list_of_groups = manager.get_list_of_all_groups()
            if list_of_groups:
                for group in list_of_groups:
                    if group.name == group_name:
                        group_id = group.id
                    
        if group_id is None:
            raise Exception(f"Provided group name {group_name} was not found in the {INTEGRATION_DISPLAY_NAME}.")
               
        group_members = manager.get_group_members(filter_value=filter_value, filter_logic=filter_logic,
                                                    group_id=group_id, limit=limit, filter_key=filter_key)
        
        if not group_members:
            result_value = False
            output_message = "No members were found for the provided criteria in Azure AD group."
        else:
            output_message = "Successfully found members for the provided criteria in Azure AD group."
            json_result = [member.raw_data for member in group_members]
            siemplify.result.add_result_json(json_result)
            siemplify.result.add_data_table("Available members of the group", construct_csv([member.to_member_csv(fields="All Fields") for member in group_members]))
            
        if filter_value is None and filter_key != SELECT_ONE_FILTER_KEY:
            output_message += "\nThe filter was not applied, because parameter \"Filter Value\" has an empty value."
            
    except Exception as e:
        siemplify.LOGGER.error('Error executing action {}.'.format(LIST_MEMBERS_IN_GROUP_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = 'Error executing action {}. Reason: {}'.format(LIST_MEMBERS_IN_GROUP_SCRIPT_NAME, e)

    if list_of_groups_csv:
        siemplify.result.add_result_json(list_of_groups_csv)
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)

if __name__ == '__main__':
    main()