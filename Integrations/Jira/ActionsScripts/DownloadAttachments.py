import base64
import json
import os

from TIPCommon import extract_configuration_param, extract_action_param

from JiraConstants import ATTACHMENT_SIZE_LIMIT_MB
from JiraConstants import INTEGRATION_IDENTIFIER, DOWNLOAD_ATTACHMENTS_SCRIPT_NAME, MAIL_ATTACHMENT_EXTENSION
from JiraManager import JiraManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from utils import get_file_path_extension, bytes_to_megabytes


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = DOWNLOAD_ATTACHMENTS_SCRIPT_NAME
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
    local_path = extract_action_param(siemplify, param_name="Download Path", is_mandatory=False, default_value=None, print_value=True)
    download_attachments_to_case_wall = extract_action_param(siemplify, param_name="Download Attachments to the Case Wall",
                                                             is_mandatory=False, default_value=False, input_type=bool, print_value=True)
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = False
    output_message = ""

    successful_attachments = []
    failed_attachments = []
    exceeding_single_attachment_size_attachments = []
    exceeding_total_size_attachments = []

    mail_attachments = []
    json_results = []

    try:
        jira = JiraManager(api_root, username, api_token, verify_ssl=verify_ssl, logger=siemplify.LOGGER)

        if local_path and not os.path.exists(local_path):
            os.makedirs(local_path)

        issue_attachments = jira.get_attachments_from_issue(issue_key)

        if issue_attachments:
            siemplify.LOGGER.info(f"Fetched {len(issue_attachments)} attachments for issue {issue_key}")

            # Extract attachments from an email
            for file_name, mail_content in issue_attachments:
                if get_file_path_extension(file_name) in MAIL_ATTACHMENT_EXTENSION:
                    try:
                        siemplify.LOGGER.info(f"Extracting attachments from email: {file_name}")
                        extracted_mail_attachments = jira.extract_attachments_from_mail(file_name, mail_content)
                        mail_attachments.extend(extracted_mail_attachments)
                        siemplify.LOGGER.info(
                            f"Successfully extracted {len(extracted_mail_attachments)} attachments from email: {file_name}")
                    except Exception as error:
                        siemplify.LOGGER.error(f"Unable to extract attachments from {file_name}: {error}")
                        siemplify.LOGGER.exception(error)
        else:
            siemplify.LOGGER.info(f"No attachments were fetched from issue {issue_key}")

        # Save found attachments to local path
        for attachment_name, attachment_content in issue_attachments + mail_attachments:
            if local_path:
                local_attachment_path = os.path.join(local_path, attachment_name)
                try:
                    siemplify.LOGGER.info(f"Saving '{attachment_name}' to local path")
                    attachment_local_path = jira.save_attachment_to_local_path(local_attachment_path, attachment_content)
                    json_results.append({"download_path": local_attachment_path})
                    successful_attachments.append(attachment_local_path)
                except Exception as error:
                    failed_attachments.append(attachment_name)
                    siemplify.LOGGER.error(f"Failed to save attachment {attachment_name} to local path {local_path}")
                    siemplify.LOGGER.exception(error)

            if download_attachments_to_case_wall:
                # Add attachment to case wall
                if bytes_to_megabytes(len(attachment_content)) < ATTACHMENT_SIZE_LIMIT_MB:
                    try:
                        siemplify.LOGGER.info(f"Attaching '{attachment_name}' to the case wall")
                        siemplify.result.add_attachment(title=attachment_name,
                                                        filename=attachment_name,
                                                        file_contents=base64.b64encode(attachment_content).decode())
                        if not local_path:
                            successful_attachments.append(attachment_name)
                    except EnvironmentError as error:
                        exceeding_total_size_attachments.append(attachment_name)
                        siemplify.LOGGER.error(error)
                        siemplify.LOGGER.exception(error)
                else:
                    exceeding_single_attachment_size_attachments.append(attachment_name)
                    siemplify.LOGGER.info(f"Attachment '{attachment_name}' is too large to attach to the case wall")

        if exceeding_single_attachment_size_attachments:
            output_message += "Downloaded Attachments files:\n {} \nexceed {} mb limit of Siemplify platform and can't be " \
                              "attached to the Case Wall\n\n".format("\n".join(exceeding_single_attachment_size_attachments),
                                                                     ATTACHMENT_SIZE_LIMIT_MB)

        if exceeding_total_size_attachments:
            output_message += "Total size of downloaded attachments exceed Siemplify platform limit of 5 mb in total, the following " \
                              "files:\n {} exceed total attachments' size\n\n".format("\n".join(exceeding_total_size_attachments))

        if successful_attachments:
            output_message += "Downloaded {} attachments. \n\nFiles:\n{}".format(len(successful_attachments),
                                                                                 "\n".join(successful_attachments))
            result_value = True
            if failed_attachments:
                output_message += "\n\nFailed to download attachments:\n  {}".format("\n  ".join(failed_attachments))
        else:
            output_message += "No attachments were downloaded"

        if json_results:
            siemplify.result.add_result_json(json.dumps(json_results))

    except Exception as error:
        output_message = "Failed to download attachments from issue {}. Error is: {}".format(issue_key, error)
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
