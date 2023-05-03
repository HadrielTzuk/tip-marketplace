import os


def save_attachment_to_local_path(path, attachment_name, attachment_content):
    """
    Save message attachment to local path
    :param path: {str} Path of the folder, where files should be saved
    :param attachment_name: {str} File name to be saved
    :param attachment_content: {str} File content
    :return: {str} Path to the downloaded files
    """
    if not os.path.exists(path):
        os.makedirs(path)
    local_path = os.path.join(path, attachment_name)
    with open(local_path, 'wb') as f:
        f.write(attachment_content)
    return local_path


def save_attachments_locally(folder, attachments_list):
    # type: (str, list) -> list
    """
    Saves files from EmailAttachmentModel objects list to Siemplify run folder and returns list of full paths to these files
    :param folder: {str} Folder where files would be saved (e.g. Siemplify run folder)
    :param attachments_list: {list} EmailAttachmentModel objects list to save locally
    :return: {str} List of full paths to saved files
    """
    saved_files = []
    for attachment in attachments_list:
        try:
            path = save_attachment_to_local_path(folder, attachment.file_name, attachment.file_contents)
            saved_files.append(path)
        except IOError as e:
            self.logger.error("Unable to save attachment {0} to the folder {1}".format(attachment.file_name, folder))
            self.logger.exception(e)

    return saved_files
