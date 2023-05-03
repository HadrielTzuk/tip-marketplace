from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from F5BIGIPiControlAPIManager import F5BIGIPiControlAPIManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, CREATE_DATA_GROUP_NAME

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_DATA_GROUP_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True, print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, is_mandatory=True, print_value=True)

    # Action parameters
    group_name = extract_action_param(siemplify, param_name="Name", is_mandatory=True, print_value=True)
    group_type = extract_action_param(siemplify, param_name="Type", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""

    try:
        manager = F5BIGIPiControlAPIManager(api_root=api_root,
                                            username=username,
                                            password=password,
                                            verify_ssl=verify_ssl,
                                            siemplify_logger=siemplify.LOGGER)

        data_group = manager.create_data_group(group_name=group_name, group_type=group_type)
        siemplify.result.add_result_json(data_group)
        output_message = f"Successfully created data group {group_name} in {INTEGRATION_DISPLAY_NAME}."

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {CREATE_DATA_GROUP_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{CREATE_DATA_GROUP_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
