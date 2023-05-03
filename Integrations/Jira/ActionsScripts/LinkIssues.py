from TIPCommon import extract_configuration_param, extract_action_param
from JiraConstants import INTEGRATION_IDENTIFIER, LINK_ISSUES_SCRIPT_NAME
from JiraRestManager import JiraRestManager
from JiraManager import JiraManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from exceptions import JiraGDPRError, JiraValidationError, JiraRelationTypeError
from utils import load_csv_to_list

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LINK_ISSUES_SCRIPT_NAME
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
    inward_issue_id = extract_action_param(siemplify, param_name="Inward Issue ID", is_mandatory=True, print_value=True)
    outward_issue_ids = extract_action_param(siemplify, param_name="Outward Issue IDs", is_mandatory=True, print_value=True)
    
    relation_type = extract_action_param(siemplify, param_name="Relation Type", default_value="Blocks", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    successfully_linked = []
    failed_linked = []
    output_message = ""
    
    try:
        outward_issue_ids = load_csv_to_list(outward_issue_ids, "Outward Issue IDs")
        try:
            #Initiate the Jira SDK connection
            jira = JiraManager(api_root, username, api_token, verify_ssl=verify_ssl)
        except Exception as e:
            try:
                #Initiate Jira-API connection
                jira = JiraRestManager(api_root, username, api_token, use_ssl=verify_ssl)
            except Exception as e:
                raise
        try:
            jira.get_issue_by_key(issue_key=inward_issue_id)
            
        except:
            raise Exception(f"Source issue {inward_issue_id} was not found in {INTEGRATION_IDENTIFIER}. Please check the spelling.")
        for outward_issue_id in outward_issue_ids:
            try:
                jira.link_issues(inward_issue_id=inward_issue_id, outward_issue_id=outward_issue_id, relation_type=relation_type)
                siemplify.LOGGER.info(f"Successfully linked the Outward Issue ID: {outward_issue_id} with the Inward Issue ID {inward_issue_id}.")
                successfully_linked.append(outward_issue_id)

            except JiraRelationTypeError as e:
                raise
            except Exception as e:
                failed_linked.append(outward_issue_id)

        if successfully_linked:
            output_message += "Successfully linked issue {} with the following issues in {}: {}.".format(
                inward_issue_id, INTEGRATION_IDENTIFIER,",".join(successfully_linked)
            )
            if failed_linked:
                output_message += "\nAction wasn't able to find the following destination issues in {}: {}".format(
                    INTEGRATION_IDENTIFIER, ",".join(failed_linked)
                )

        else:
            output_message += f"None of the destination issues were found in {INTEGRATION_IDENTIFIER}."
            result_value = False

    except Exception as error:
        output_message = f"Error executing action {LINK_ISSUES_SCRIPT_NAME}. Reason: {error}"
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
