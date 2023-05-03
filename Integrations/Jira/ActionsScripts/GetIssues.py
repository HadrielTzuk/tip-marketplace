import json

from JiraConstants import INTEGRATION_IDENTIFIER, GET_ISSUES_SCRIPT_NAME
from JiraManager import JiraManager
from TIPCommon import extract_configuration_param, extract_action_param
from utils import load_csv_to_list

from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_ISSUES_SCRIPT_NAME
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
    issue_keys = extract_action_param(siemplify, param_name="Issue Keys", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED

    try:
        issues_keys = load_csv_to_list(issue_keys, "Issue Keys")
        jira = JiraManager(api_root, username, api_token, verify_ssl=verify_ssl)
        issues_details_list = []
        successful_issues = []
        failed_issues = []
        json_results = []

        for issue_key in issues_keys:
            try:
                siemplify.LOGGER.info(f"Fetching details for issue {issue_key}")
                issue_object = jira.get_issue_by_key(issue_key)
                siemplify.LOGGER.info(f"Successfully fetched details for issue {issue_key}")

                issue_details = issue_object.raw_fields
                json_results.append(issue_details)

                # Attach issue details
                siemplify.result.add_json("Issue Details - {0}".format(issue_key), json.dumps(issue_details))
                siemplify.result.add_result_json(json_results)
                successful_issues.append(issue_key)
                issues_details_list.append({issue_key: issue_details})

            except Exception as error:
                siemplify.LOGGER.error(f"Failed to get issue of issue key {issue_key}")
                siemplify.LOGGER.exception(error)
                failed_issues.append(issue_key)

        if issues_details_list:
            output_message = "Successfully get issue details. Issues: {0}\n".format(', '.join(successful_issues))
        else:
            output_message = "Can not get issues details"

        if issues_details_list and failed_issues:
            output_message += "Failed to get issue details. Issues: {}".format(', '.join(failed_issues))

        result_value = json.dumps(issues_details_list)

    except Exception as error:
        output_message = "Failed to get issues for {}. Error is: {}".format(issue_keys, error)
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
