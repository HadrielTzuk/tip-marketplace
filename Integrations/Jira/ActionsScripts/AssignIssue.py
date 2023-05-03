from TIPCommon import extract_configuration_param, extract_action_param

from JiraConstants import INTEGRATION_IDENTIFIER, ASSIGN_ISSUE_SCRIPT_NAME
from JiraManager import JiraManager
from JiraRestManager import JiraRestManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from exceptions import JiraGDPRError, JiraValidationError


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ASSIGN_ISSUE_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Integration Configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name='Api Root',
                                           is_mandatory=True,
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name='Username',
                                           is_mandatory=True,
                                           print_value=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name='Api Token',
                                            is_mandatory=True,
                                            print_value=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name='Verify SSL',
                                             default_value=False, input_type=bool)
    # Action parameters
    issue_key = extract_action_param(siemplify, param_name="Issue Key", is_mandatory=True, print_value=True)
    assignee = extract_action_param(siemplify, param_name="Assignee", is_mandatory=True, print_value=True)
    initiator = extract_action_param(siemplify, param_name="Jira Username", is_mandatory=False, default_value=None, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        jira = JiraManager(api_root, username, api_token, verify_ssl=verify_ssl)
        siemplify.LOGGER.info(f"Assigning issue {issue_key} to {assignee}")

        # On-prem: get User
        user_assignee = ''
        try:
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

            jira.assign_issue(issue_key, user_assignee)
            siemplify.LOGGER.info(f"Successfully assigned issue")

        except JiraGDPRError as error:
            siemplify.LOGGER.info(error)
            siemplify.LOGGER.info("Trying to locate user's accountId")
            rest_manager = JiraRestManager(server_addr=api_root,
                                           username=username,
                                           api_token=api_token)

            jira_users = rest_manager.get_all_users()

            user_account_id = ''
            for user in jira_users:
                if (user.email_address and user.email_address == assignee) or (
                        user.display_name and user.display_name == assignee):
                    siemplify.LOGGER.info("User {} found.".format(assignee))
                    user_account_id = user.account_id
                    break

            if not user_account_id:
                raise JiraValidationError("User {} does not exist.".format(assignee))

            rest_manager.assign_issue(issue_key, user_account_id)

        if initiator:
            try:
                siemplify.LOGGER.info(f"Adding comment of issue assignment for initiator {initiator}")
                jira.add_comment(issue_key, f"[~{initiator}] assigned issue {issue_key} to {assignee}.")
                siemplify.LOGGER.info(f"Successfully created issue comment")
            except Exception as error:
                siemplify.LOGGER.error(f"Failed to add comment of issue assignment for initiator {initiator}")
                siemplify.LOGGER.exception(error)

        output_message = f"Successfully assigned issue {issue_key} to {assignee}."

    except JiraValidationError as error:
        output_message = "Action wasn't able to assign issue to {}. Error is {}".format(assignee, error)
        result_value = False
        status = EXECUTION_STATE_COMPLETED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    except Exception as error:
        output_message = "Failed to assign issue to {}. Error is: {}".format(assignee, error)
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
