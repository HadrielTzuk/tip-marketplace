from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from JiraRestManager import JiraRestManager
from JiraManager import JiraManager
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from JiraConstants import INTEGRATION_IDENTIFIER, LIST_RELATION_TYPES_SCRIPT_NAME, FILTER_KEY_VALUES, \
    FILTER_STRATEGY_MAPPING
from TIPCommon import construct_csv
from exceptions import JiraGDPRError


TABLE_NAME = "Available Relation Types"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_RELATION_TYPES_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Integration configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name="Api Root",
                                           is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name="Username",
                                           is_mandatory=True, print_value=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name="Api Token",
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, default_value=False, print_value=True)

    # Action parameters
    filter_key = extract_action_param(siemplify, param_name="Filter Key", print_value=True)
    filter_logic = extract_action_param(siemplify, param_name="Filter Logic", print_value=True)
    filter_value = extract_action_param(siemplify, param_name="Filter Value", print_value=True)
    limit = extract_action_param(siemplify, param_name="Max Records To Return", input_type=int, default_value=50,
                                 print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED

    try:
        if not FILTER_KEY_VALUES.get(filter_key) and FILTER_STRATEGY_MAPPING.get(filter_logic):
            raise Exception("you need to select a field from the \"Filter Key\" parameter")

        if limit <= 0:
            raise Exception(f"Invalid value was provided for \"Max Records to Return\": {limit}. "
                            f"Positive number should be provided")

        manager = JiraManager(api_root, username, api_token, verify_ssl=verify_ssl)

        try:
            relation_types = manager.get_relation_types(filter_key, filter_logic, filter_value, limit)
        except JiraGDPRError as error:
            siemplify.LOGGER.info(error)
            rest_manager = JiraRestManager(api_root, username, api_token, use_ssl=verify_ssl)
            relation_types = rest_manager.get_relation_types(filter_key, filter_logic, filter_value, limit)

        if relation_types:
            siemplify.result.add_data_table(TABLE_NAME, construct_csv([relation_type.to_table()
                                                                       for relation_type in relation_types]))
            siemplify.result.add_result_json([relation_type.as_json() for relation_type in relation_types])
            output_message = f"Successfully found relation types for the provided criteria in {INTEGRATION_IDENTIFIER}."
        else:
            result = False
            output_message = f"No relation types were found for the provided criteria in {INTEGRATION_IDENTIFIER}."

        if FILTER_KEY_VALUES.get(filter_key) and FILTER_STRATEGY_MAPPING.get(filter_logic) and not filter_value:
            output_message += "\nThe filter was not applied, because parameter \"Filter Value\" has an empty value."

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {LIST_RELATION_TYPES_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{LIST_RELATION_TYPES_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
