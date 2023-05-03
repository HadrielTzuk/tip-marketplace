from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from FileOperationManager import FileOperationManager
from SiemplifyAction import *


@output_handler
def main():
    siemplify = SiemplifyAction()
    file_manager = FileOperationManager()
    source_folder = siemplify.parameters['source_folder']
    file_filter = siemplify.parameters['file_filter']
    output_folder = siemplify.parameters['output_folder']
    tarzip_file_path = file_manager.targz_windows(source_folder, file_filter, output_folder)

    output_message = "Successfully created {0}".format(tarzip_file_path)
    siemplify.end(output_message, tarzip_file_path)


if __name__ == '__main__':
    main()