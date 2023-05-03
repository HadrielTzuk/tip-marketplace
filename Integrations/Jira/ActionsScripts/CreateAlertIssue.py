import json

from TIPCommon import extract_configuration_param, extract_action_param

from JiraConstants import INTEGRATION_IDENTIFIER, CREATE_ALERT_ISSUE_SCRIPT_NAME, JIRA_TAG
from JiraManager import JiraManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_ALERT_ISSUE_SCRIPT_NAME
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
    project_key = extract_action_param(siemplify, param_name="Project Key", is_mandatory=True, print_value=True)
    summary = extract_action_param(siemplify, param_name="Summary", is_mandatory=True, print_value=True)
    issue_type = extract_action_param(siemplify, param_name="Issue Type", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED

    try:

        if not siemplify.current_alert:
            raise Exception("Create Alert Issue can not run on case, only on alerts")

        jira = JiraManager(api_root, username, api_token, verify_ssl=verify_ssl)

        context_alert_id = siemplify.current_alert.external_id
        issue_key = jira.create_issue(project_key=project_key, summary=summary, issue_type=issue_type, description=context_alert_id)

        if issue_key:
            siemplify.add_tag(JIRA_TAG)

            output_message = f"Successfully created issue {issue_key}."
            result_value = issue_key

            issue_object = jira.get_issue_by_key(issue_key)
            siemplify.result.add_result_json(json.dumps(issue_object.raw_fields))
            siemplify.update_alerts_additional_data({siemplify.current_alert.identifier: issue_key})
        else:
            output_message = "Failed to create Jira issue."
            result_value = None

    except Exception as error:
        output_message = "Failed to create an alert issue for project {}. Error is: {}".format(project_key, error)
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
