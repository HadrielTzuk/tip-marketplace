from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from FileOperationManager import FileOperationManager
from SiemplifyAction import *


@output_handler
def main():
    siemplify = SiemplifyAction()
    file_manager = FileOperationManager()
    source_win_file = siemplify.parameters['source_win_file_path']
    dest_linux_path = siemplify.parameters['dest_linux_path']
    dest_linux_ip = siemplify.parameters['dest_linux_ip']
    dest_linux_username = siemplify.parameters['dest_linux_username']
    dest_linux_password = siemplify.parameters['dest_linux_password']
    keep_file = siemplify.parameters['keep_file']
    dest_path = file_manager.transfer_file_win_to_unix(source_win_file, dest_linux_ip, dest_linux_username,
                                                             dest_linux_password, dest_linux_path, keep_file)

    output_message = "Transfer File {0} to -> {1} completed ".format(source_win_file, dest_linux_path)
    siemplify.end(output_message, dest_path)


if __name__ == '__main__':
    main()