from TIPCommon import extract_configuration_param, extract_action_param

from JiraConstants import INTEGRATION_IDENTIFIER, UPLOAD_ATTACHMENT_SCRIPT_NAME
from JiraManager import JiraManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from utils import load_csv_to_list


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPLOAD_ATTACHMENT_SCRIPT_NAME
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
    file_paths = extract_action_param(siemplify, param_name="File Paths", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    successful_uploads = []
    failed_uploads = []

    try:
        jira = JiraManager(api_root, username, api_token, verify_ssl=verify_ssl, logger=siemplify.LOGGER)
        file_paths = load_csv_to_list(file_paths, "File Paths")

        for file_path in file_paths:
            try:
                jira.upload_attachment(issue_key, file_path)
                successful_uploads.append(file_path)
            except Exception as error:
                siemplify.LOGGER.error(f"Unable to upload path {file_path}.")
                siemplify.LOGGER.exception(error)
                failed_uploads.append(file_path)

        if successful_uploads:
            output_message = "Successfully uploaded the following files:\n  {}".format("\n  ".join(successful_uploads))
            if failed_uploads:
                output_message += "\n\nFailed to upload the following files:\n  {}".format("\n  ".join(failed_uploads))
        else:
            output_message = "No files were uploaded"

    except Exception as error:
        output_message = "Failed to upload files to issue {}. Error is: {}".format(issue_key, error)
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
