from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from MicrosoftGraphSecurityManager import MicrosoftGraphSecurityManager
from TIPCommon import extract_configuration_param, extract_action_param
import datamodels


INTEGRATION_NAME = "MicrosoftGraphSecurity"
SCRIPT_NAME = "Update Alert"
SPLIT_CHAR = ","


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            is_mandatory=True, input_type=str)
    secret_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Secret ID",
                                            is_mandatory=False, input_type=str)
    certificate_path = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                   param_name="Certificate Path", is_mandatory=False, input_type=str)
    certificate_password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                       param_name="Certificate Password", is_mandatory=False,
                                                       input_type=str)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Tenant",
                                         is_mandatory=True, input_type=str)

    alert_id = extract_action_param(siemplify, param_name='Alert ID', input_type=str, is_mandatory=True,
                                    print_value=True)
    assigned_to = extract_action_param(siemplify, param_name='Assigned To', input_type=str, is_mandatory=False,
                                       print_value=True)
    closed_date_time = extract_action_param(siemplify, param_name='Closed Date Time', input_type=str,
                                            is_mandatory=False,
                                            print_value=True)
    comments = extract_action_param(siemplify, param_name='Comments', input_type=str, is_mandatory=False,
                                    print_value=True)
    feedback = extract_action_param(siemplify, param_name='Feedback', input_type=str, is_mandatory=False,
                                    print_value=True)
    status = extract_action_param(siemplify, param_name='Status', input_type=str, is_mandatory=False,
                                  print_value=True)
    tags = extract_action_param(siemplify, param_name='Tags', input_type=str, is_mandatory=False,
                                print_value=True)

    comments_list = []
    tags_list = []

    if comments:
        comments_list = [comment.strip() for comment in comments.split(SPLIT_CHAR)]

    if tags:
        tags_list = [tag.strip() for tag in tags.split(SPLIT_CHAR)]

    if feedback and feedback not in datamodels.VALID_ALERT_FEEDBACKS:
        output_message = f"Feedback {feedback} is invalid. Valid values are: {', '.join(datamodels.VALID_ALERT_FEEDBACKS)}. Aborting."
        siemplify.LOGGER.error(output_message)
        siemplify.end(output_message, 'false', EXECUTION_STATE_FAILED)

    if status and status not in datamodels.VALID_ALERT_STATUSES:
        output_message = f"Status {status} is invalid. Valid values are: {', '.join(datamodels.VALID_ALERT_STATUSES)}. Aborting."
        siemplify.LOGGER.error(output_message)
        siemplify.end(output_message, 'false', EXECUTION_STATE_FAILED)

    valid_comments = []
    for comment in comments_list:
        if comment not in datamodels.VALID_ALERT_COMMENTS:
            siemplify.LOGGER.warn(
                f"Comment \"{comment}\" is invalid. Valid values are: {', '.join(datamodels.VALID_ALERT_COMMENTS)}. Comment will be ignored.")
        else:
            valid_comments.append(comment)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        siemplify.LOGGER.info("Connecting to Microsoft Graph Security.")
        mtm = MicrosoftGraphSecurityManager(client_id, secret_id, certificate_path, certificate_password, tenant)
        siemplify.LOGGER.info("Connected successfully.")

        siemplify.LOGGER.info(f"Updating alert {alert_id}")
        alert_after_update = mtm.update_alert(alert_id, assigned_to=assigned_to, closed_date_time=closed_date_time,
                                              comments=valid_comments, feedback=feedback, status=status, tags=tags_list)

        if alert_after_update:
            output_message = f"Alert {alert_id} was successfully updated."
            siemplify.LOGGER.info(output_message)
            result_value = 'true'

        else:
            output_message = f"Failed to update alert {alert_id}."
            siemplify.LOGGER.info(output_message)
            result_value = 'false'

        action_status = EXECUTION_STATE_COMPLETED

    except Exception as e:
        siemplify.LOGGER.error(f"Some errors occurred. Error: {e}")
        siemplify.LOGGER.exception(e)
        action_status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = f"Some errors occurred. Error: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {action_status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, action_status)


if __name__ == "__main__":
    main()
