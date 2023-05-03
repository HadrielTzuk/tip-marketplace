from SiemplifyUtils import output_handler
from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import delete_older_files_from_folder
import os

@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = 'Siemplify - Delete Case Files History'
    days_backwards = int(siemplify.parameters.get("Days", 3))

    siemplify.LOGGER.info("-----Job Started-----")

    if 'win' in os.environ.get('OS', '').lower():
        folders = [
            r"I:\Siemplify_Channels\Cases\Done",
            r"I:\Siemplify_Channels\Cases\Error",
        ]
    else:
        folders = [
            r"/i/Siemplify_Channels/Cases/Done",
            r"/i/Siemplify_Channels/Cases/Error",
        ]

    for folder in folders:
        try:
            siemplify.LOGGER.info("Deleting files from {}".format(folder))
            delete_older_files_from_folder(folder, days_backwards)
        except Exception as e:
            siemplify.LOGGER.error("Unable to delete files from {}".format(folder))
            siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info("-----Job Finished-----")


if __name__ == '__main__':
    main()
