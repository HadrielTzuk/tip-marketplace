import json

from JiraRestManager import JiraRestManager
from TIPCommon import extract_configuration_param, extract_action_param

from JiraConstants import INTEGRATION_IDENTIFIER, UPDATE_ISSUE_SCRIPT_NAME
from JiraManager import JiraManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from exceptions import JiraValidationError, JiraGDPRError
from utils import load_csv_to_list


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_ISSUE_SCRIPT_NAME
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
    summary = extract_action_param(siemplify, param_name="Summary", is_mandatory=False, print_value=True)
    description = extract_action_param(siemplify, param_name="Description", is_mandatory=False, print_value=True)
    issue_type = extract_action_param(siemplify, param_name="Issue Type", is_mandatory=False, print_value=True)
    initiator = extract_action_param(siemplify, param_name="Jira Username", is_mandatory=False, print_value=True)
    issue_status = extract_action_param(siemplify, param_name="Status", is_mandatory=False, print_value=True)
    assignee = extract_action_param(siemplify, param_name="Assignee", is_mandatory=False, print_value=True)
    components = extract_action_param(siemplify, param_name="Components", is_mandatory=False, print_value=True)
    labels = extract_action_param(siemplify, param_name="Labels", is_mandatory=False, print_value=True)
    custom_fields = extract_action_param(siemplify, param_name="Custom Fields", is_mandatory=False, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED

    result_value = True

    components_list_to_api_call = None
    try:
        try:
            custom_fields_dict = json.loads(custom_fields) if custom_fields else {}
        except Exception:
            raise Exception("Invalid JSON payload provided in the parameter \"Custom Fields\". "
                            "Please check the structure.")

        jira = JiraManager(api_root, username, api_token, verify_ssl=verify_ssl)

        if components:
            # Extract project key
            siemplify.LOGGER.info("Fetching issue to extract the project key")
            issue_object = jira.get_issue_by_key(issue_key)
            siemplify.LOGGER.info("Successfully fetched the issue to extract the project key")
            project_key = issue_object.project_key

            # Extract components ids
            components_list = load_csv_to_list(components, "Components")
            siemplify.LOGGER.info(f"Fetching {project_key} components")
            project_components = jira.get_project_components(project=project_key)
            siemplify.LOGGER.info(f"Successfully fetched {project_key} components")

            existing_components = [component for component in project_components if component.name in components_list]
            existing_components_names = [component.name for component in existing_components]
            not_existing_components = [component_name for component_name in list(set(components_list)) if
                                       component_name not in existing_components_names]

            if not_existing_components:
                raise JiraValidationError(
                    f"Failed to create Jira issue because specified components: {', '.join(not_existing_components)} "
                    f"was not found.")

            components_list_to_api_call = [{"id": component.id} for component in existing_components]

        labels_list = load_csv_to_list(labels, "Labels") if labels else None

        # On-prem: get User
        user_assignee = ''
        try:
            if assignee:
                users = jira.get_users_contains_username(username=assignee)
                for user in users:
                    if (user.email_address and user.email_address == assignee) or (
                            user.display_name and user.display_name == assignee) or (
                            user.raw_data.get("name", '') == assignee
                    ):
                        siemplify.LOGGER.info("User {} found.".format(assignee))
                        user_assignee = user.raw_data.get('name')
                        break

                if not user_assignee:
                    raise JiraValidationError("User {} does not exist.".format(assignee))

            siemplify.LOGGER.info(f"Updating issue of type {issue_type} with key {issue_key}")
            jira.update_issue(issue_key, summary, description, issue_type, issue_status, components_list_to_api_call,
                              labels_list, custom_fields_dict)
            siemplify.LOGGER.info(f"Successfully updated issue of type {issue_type} with key {issue_key}")

            if user_assignee:
                try:
                    siemplify.LOGGER.info(
                        f"Assigning issue of type {issue_type} with key {issue_key} to {assignee}")
                    jira.assign_issue(issue_key, assignee=user_assignee)
                    siemplify.LOGGER.info(
                        f"Successfully assigned issue of type {issue_type} with key {issue_key} to {assignee}")

                except Exception as error:
                    siemplify.LOGGER.error(
                        f"Failed to assign issue of type {issue_type} with key {issue_key} to {assignee}")
                    siemplify.LOGGER.exception(error)

        # Cloud option
        except JiraGDPRError as error:
            siemplify.LOGGER.info(error)
            jira = JiraRestManager(api_root, username, api_token, use_ssl=verify_ssl)

            siemplify.LOGGER.info("Trying to locate user's accountId")

            # Cloud: get User
            user_assignee = ''
            if assignee:
                siemplify.LOGGER.info("Finding user's account id")
                jira_users = jira.get_all_users()

                for user in jira_users:
                    if (user.email_address and user.email_address == assignee) or (
                            user.display_name and user.display_name == assignee):
                        siemplify.LOGGER.info("User {} found.".format(assignee))
                        user_assignee = user.account_id
                        break

                if not user_assignee:
                    raise JiraValidationError("User {} does not exist.".format(assignee))

            siemplify.LOGGER.info(f"Updating issue of type {issue_type} with key {issue_key}")
            jira.update_issue(issue_key, summary, description, issue_type, issue_status, components_list_to_api_call,
                              labels_list, custom_fields_dict)
            siemplify.LOGGER.info(f"Successfully updated issue of type {issue_type} with key {issue_key}")

            if user_assignee and issue_key:
                try:
                    siemplify.LOGGER.info(
                        f"Assigning issue of type {issue_type} with key {issue_key} to {assignee}")
                    jira.assign_issue(issue_key, assignee_account_id=user_assignee)
                    siemplify.LOGGER.info(
                        f"Successfully assigned issue of type {issue_type} with key {issue_key} to {assignee}")

                except Exception as error:
                    siemplify.LOGGER.error(
                        f"Failed to assign issue of type {issue_type} with key {issue_key} to {assignee}")
                    siemplify.LOGGER.exception(error)

            result_value = issue_key

        try:
            siemplify.LOGGER.info(f"Adding comment of issue update for initiator {initiator}")
            jira.add_comment(issue_key, f"[~{initiator}] updated issue {issue_key}.")
            siemplify.LOGGER.info(f"Successfully update issue comment")
        except Exception as error:
            siemplify.LOGGER.error(f"Failed to add comment of issue update for initiator {initiator}")
            siemplify.LOGGER.exception(error)

        try:
            siemplify.LOGGER.info(f"Retrieving issue details for updated issue with key {issue_key}")
            issue_object = jira.get_issue_by_key(issue_key)
            siemplify.LOGGER.info(f"Successfully updated issue details")
            siemplify.result.add_result_json(json.dumps(issue_object.raw_fields))
        except Exception as error:
            siemplify.LOGGER.error(f"Failed to fetch issue details for updated issue {issue_key}")
            siemplify.LOGGER.exception(error)

        output_message = f"Successfully updated issue {issue_key}."

    except JiraValidationError as error:
        output_message = "Action wasn't able to update issue {}. Error is: {}".format(issue_key, error)
        result_value = False
        status = EXECUTION_STATE_COMPLETED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    except Exception as error:
        output_message = "Failed to update to issue {}. Error is: {}".format(issue_key, error)
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
