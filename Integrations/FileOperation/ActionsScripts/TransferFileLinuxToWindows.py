from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from FileOperationManager import FileOperationManager
from SiemplifyAction import *


@output_handler
def main():
    siemplify = SiemplifyAction()
    file_manager = FileOperationManager()
    source_linux_file = siemplify.parameters['source_linux_file_path']
    source_linux_ip = siemplify.parameters['source_linux_ip']
    source_linux_username = siemplify.parameters['source_linux_username']
    source_linux_password = siemplify.parameters['source_linux_password']
    dest_win_path = siemplify.parameters['dest_win_path']
    keep_file = siemplify.parameters['keep_file']
    dest_path = file_manager.transfer_file_unix_to_win(source_linux_ip, source_linux_username,
                                                             source_linux_password, source_linux_file,
                                                             dest_win_path, keep_file)

    output_message = "Transfer File {0} to -> {1} completed ".format(source_linux_file, dest_win_path)
    siemplify.end(output_message, dest_path)


if __name__ == '__main__':
    main()