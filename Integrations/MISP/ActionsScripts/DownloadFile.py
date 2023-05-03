import os
from MISPManager import MISPManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from constants import DOWNLOAD_FILE_SCRIPT_NAME, INTEGRATION_NAME, CASE_WALL_DOWNLOADED_FILES_TITLE
from exceptions import AttachmentExistsException, MISPManagerEventIdNotFoundError
from utils import save_attachment


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = DOWNLOAD_FILE_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root")
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key")
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Use SSL",
                                          default_value=False, input_type=bool)
    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="CA Certificate File - parsed into Base64 String")

    event_id = extract_action_param(siemplify, param_name="Event ID", print_value=True)

    download_folder_path = extract_action_param(siemplify, param_name="Download Folder Path", print_value=True)
    overwrite = extract_action_param(siemplify, param_name="Overwrite", print_value=True, input_type=bool,
                                     default_value=False)

    id_type = 'ID' if event_id.isdigit() else 'UUID'

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    successful_downloads, limit_failed_downloads = [], []

    try:
        misp_manager = MISPManager(api_root, api_token, use_ssl, ca_certificate)

        request_event_id = misp_manager.get_event_by_id_or_raise(event_id).id

        siemplify.LOGGER.info("Downloading samples for event {}".format(event_id))
        samples_details = misp_manager.download_sample(request_event_id)

        if download_folder_path and not overwrite:
            existing_files = []
            for attachment in samples_details:
                if os.path.exists('{}/{}'.format(download_folder_path, attachment.filename)):
                    existing_files.append(attachment.filename)

            if existing_files:
                raise AttachmentExistsException("The following files already exist: {}. "
                                                "Please remove them or set parameter “Overwrite“ to true."
                                                .format(', '.join(existing_files)))

        if not download_folder_path:
            siemplify.LOGGER.info("Found {} samples.".format(len(samples_details)))
            for attachment in samples_details:
                try:
                    siemplify.result.add_attachment(CASE_WALL_DOWNLOADED_FILES_TITLE.format(event_id),
                                                    attachment.filename,
                                                    attachment.content)
                    successful_downloads.append(attachment.filename)
                except Exception as err:
                    limit_failed_downloads.append(attachment.filename)
                    siemplify.LOGGER.error('Action wasn’t able to download the following file, because they exceeded '
                                           'the limit of 3 MB: {}'.format(attachment.filename))
                    siemplify.LOGGER.exception(err)
        else:
            for attachment in samples_details:
                save_attachment(path=download_folder_path, name=attachment.filename, content=attachment.content)
                successful_downloads.append(attachment.filename)
            if samples_details:
                siemplify.result.add_result_json({'absolute_paths': ['{}/{}'
                                                 .format(download_folder_path, attachment.filename)
                                                                     for attachment in samples_details]})

        if successful_downloads:
            output_message += "Successfully downloaded the following files from the event with {} {} in {}:\n {} \n"\
                .format(id_type, event_id, INTEGRATION_NAME, ', '.join(successful_downloads))

        if limit_failed_downloads:
            output_message += "Action wasn’t able to download the following files, because they exceeded the limit " \
                              "of 3 MB: \n {}. \n Please specify a folder path in the parameter “Download Folder " \
                              "Path“ in order to download them.".format(', '.join(limit_failed_downloads))

        if not successful_downloads:
            output_message += "No files were found for the event with {} {} in {}"\
                .format(id_type, event_id, INTEGRATION_NAME)
            result_value = False

    except Exception as e:
        output_message = "Error executing action {}. Reason: ".format(DOWNLOAD_FILE_SCRIPT_NAME)
        output_message += 'Event with {} {} was not found in {}'.format(id_type, event_id, INTEGRATION_NAME) \
            if isinstance(e, MISPManagerEventIdNotFoundError) else str(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
