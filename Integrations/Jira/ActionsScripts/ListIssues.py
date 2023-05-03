import json

from TIPCommon import extract_configuration_param, extract_action_param

from JiraConstants import INTEGRATION_IDENTIFIER, LIST_ISSUES_SCRIPT_NAME, DEFAULT_DATE_FORMAT
from JiraManager import JiraManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from utils import load_csv_to_list

SPLIT_CHAR = ","


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_ISSUES_SCRIPT_NAME
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
    summary = extract_action_param(siemplify, param_name="Summary", is_mandatory=False, print_value=True)
    description = extract_action_param(siemplify, param_name="Description", is_mandatory=False, print_value=True)
    reporter = extract_action_param(siemplify, param_name="Reporter", is_mandatory=False, print_value=True)
    updated_from = extract_action_param(siemplify, param_name="Updated From", default_value=DEFAULT_DATE_FORMAT, is_mandatory=False,
                                        print_value=True)
    created_from = extract_action_param(siemplify, param_name="Created From", default_value=DEFAULT_DATE_FORMAT, is_mandatory=False,
                                        print_value=True)
    project_names = extract_action_param(siemplify, param_name="Project Names", is_mandatory=False, print_value=True)
    issue_types = extract_action_param(siemplify, param_name="Issue Types", is_mandatory=False, print_value=True)
    priorities = extract_action_param(siemplify, param_name="Priorities", is_mandatory=False, print_value=True)
    assignees = extract_action_param(siemplify, param_name="Assignees", is_mandatory=False, print_value=True)
    statuses = extract_action_param(siemplify, param_name="Statuses", is_mandatory=False, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED

    try:
        jira = JiraManager(api_root, username, api_token, verify_ssl=verify_ssl, logger=siemplify.LOGGER)

        project_names_list = load_csv_to_list(project_names, "Project Names") if project_names else None
        issue_types_list = load_csv_to_list(issue_types, "Issue Types") if issue_types else None
        priority_list = load_csv_to_list(priorities, "Priorities") if priorities else None
        assignee_list = load_csv_to_list(assignees, "Assignees") if assignees else None
        status_list = load_csv_to_list(statuses, "Statuses") if statuses else None

        siemplify.LOGGER.info(f"Fetching issues with provided filter parameters")
        issues_keys = jira.list_issues(project_key_list=project_names_list,
                                       assignee_list=assignee_list,
                                       issue_type_list=issue_types_list,
                                       priority_list=priority_list,
                                       status_list=status_list,
                                       summary=summary,
                                       description=description,
                                       reporter=reporter,
                                       created_from=created_from if created_from != DEFAULT_DATE_FORMAT else None,
                                       updated_from=updated_from if updated_from != DEFAULT_DATE_FORMAT else None)

        siemplify.LOGGER.info(f"Successfully fetched {len(issues_keys)} issues")

        if issues_keys:
            output_message = f"Found {len(issues_keys)} issues: {', '.join(issues_keys)}."
            result_value = json.dumps(issues_keys)
            siemplify.result.add_result_json(json.dumps(issues_keys))
        else:
            output_message = "No issues were found for the provided filter parameters."
            result_value = False

    except Exception as error:
        output_message = "Failed to list issues. Error is: {}".format(error)
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
