from TIPCommon import extract_configuration_param, extract_action_param

from JiraConstants import INTEGRATION_IDENTIFIER, ADD_COMMENT_SCRIPT_NAME
from JiraManager import JiraManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_COMMENT_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Integration Configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name='Api Root', is_mandatory=True,
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name='Username', is_mandatory=True,
                                           print_value=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name='Api Token', is_mandatory=True,
                                            print_value=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name='Verify SSL',
                                             default_value=False, input_type=bool)
    # Action parameters
    issue_key = extract_action_param(siemplify, param_name="Issue Key", is_mandatory=True, print_value=True)
    comment = extract_action_param(siemplify, param_name="Comment", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED

    try:
        jira = JiraManager(api_root, username, api_token, verify_ssl=verify_ssl)
        comment_id = jira.add_comment(issue_key, comment)
        output_message = f"Successfully added comment {comment_id}"
        result_value = comment_id
    except Exception as error:
        output_message = "Failed to add comment to issue {}. Error is: {}".format(issue_key, error)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
