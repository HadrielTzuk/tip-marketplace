from SiemplifyUtils import output_handler
# Imports.
from SiemplifyJob import SiemplifyJob
import SiemplifyUtils
import os
from SiemplifyUtils import dict_to_flat, flat_dict_to_csv
from datetime import datetime

# Providers and strings.
MONITORING_PROVIDER = 'Siemplify'
FILE_TIME_FORMAT = "%Y-%m-%d_%H-%M-%S"
MAX_CSV_DEFAULT_COUNT = 100
FILE_NAME = "Measurement Monitor_{0}.csv"
MAIL_DEFAULT_NAME = "MeasurementReport.csv"
WIN_FILE_DEFAULT_PATH = r"C:\Siemplify_Server\Metrics"
LINUX_FILE_DEFAULT_PATH = r"/opt/siemplify/siemplify_server/Metrics"
WINDOWS_STRING = 'win'
OS_FIELD_SYSTEM_INFO = 'OS'

# Messages.
MAIL_SUBJECT_PATTERN = "Measurement Monitor Job's Report"


def build_email_message(start_time_unix, end_time_unix):
    starttime_dt = SiemplifyUtils.convert_unixtime_to_datetime(start_time_unix)
    endtime_dt = SiemplifyUtils.convert_unixtime_to_datetime(end_time_unix)

    message = "\nHi," \
              " \n this is an automated message from Siemplify's Measurement Monitor Job.\r" \
              " Attached a csv measurement report from {0} to {1}".format(starttime_dt, endtime_dt)

    return message


def retention_files(siemplify, folder_path):
    try:
        max_files_count = int(siemplify.parameters.get("Max CSV Files Count Retention", MAX_CSV_DEFAULT_COUNT))
        # scan the folder
        path, dirs, files = next(os.walk(folder_path))
        file_count = len(files)
        # check if there are more then X files
        if file_count > max_files_count:
            # first the oldest
            sorted_files = sorted(files, key=lambda name: os.path.getmtime(os.path.join(path, name)))
            # filter files by extension
            sorted_files = [f for f in sorted_files if os.path.splitext(f)[1] == '.csv']

            # delete the oldest ones (only csv files of his own instance)
            delete_count = file_count - max_files_count
            siemplify.LOGGER.info(
                "There are more then {0} files in {1} folder. Delete the {2} oldest ones".format(max_files_count,
                                                                                                 folder_path,
                                                                                                 delete_count))
            for metrics_file_name in sorted_files[:delete_count]:
                siemplify.LOGGER.info("Deleting {0} file.".format(metrics_file_name))
                os.remove(os.path.join(folder_path, metrics_file_name))
                siemplify.LOGGER.info("{0} Deleted".format(metrics_file_name))
    except Exception as e:
        siemplify.LOGGER.error("Files Retention Fail")
        siemplify.LOGGER.exception(e)


def save_metrics_to_local_file(siemplify, measurement_csv, folder_path):
    try:
        # check if exists
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

        file_name = FILE_NAME.format(datetime.now().strftime(FILE_TIME_FORMAT))
        file_full_path = os.path.join(folder_path, file_name)
        with open(file_full_path, 'w') as f:
            f.write(measurement_csv)
        siemplify.LOGGER.info("Successfully write metrics to {0}".format(file_full_path))

    except Exception as e:
        siemplify.LOGGER.error("Failed to write metrics to {0}".format(folder_path))
        siemplify.LOGGER.exception(e)


def send_mail(siemplify, mail_message, measurement_csv):
    try:
        if not (measurement_csv):
            attachment_string = ""
        else:
            attachment_string = measurement_csv

        recipients = siemplify.get_configuration(MONITORING_PROVIDER).get('Recipients').split(",")
        siemplify.send_mail(MAIL_SUBJECT_PATTERN, mail_message, recipients, MAIL_DEFAULT_NAME, str(attachment_string))


    except Exception as e:
        siemplify.LOGGER.warn(e)


def dict_to_csv_string(target_dict):
    """
    Convert dict to CSV string.
    :param target_dict: {dict} Target dict.
    :return: {str} String CSV.
    """
    output_str = ""
    flat_dict = dict_to_flat(target_dict)
    csv_list = flat_dict_to_csv(flat_dict)
    for line in csv_list[1:]:
        output_str = output_str + " \n {}".format(line)
    return output_str


@output_handler
def main():
    siemplify = SiemplifyJob()

    siemplify.script_name = "Measurement_Monitor"
    siemplify.LOGGER.info("--- Measurement Monitor started ---")

    # fix_paths
    if WINDOWS_STRING in os.environ.get(OS_FIELD_SYSTEM_INFO, '').lower():
        folder_path = siemplify.parameters.get("Metrics Output Folder") if siemplify.parameters.get("Metrics Output Folder") else WIN_FILE_DEFAULT_PATH
    else:
        folder_path = siemplify.parameters.get("Metrics Output Folder") if siemplify.parameters.get("Metrics Output Folder") else LINUX_FILE_DEFAULT_PATH

    try:
        # Get Time Range.
        unix_ms_last_run_time = siemplify.fetch_timestamp()
        unix_ms_now = SiemplifyUtils.unix_now()

        measurement_json = siemplify.get_system_info(unix_ms_last_run_time)
        measurement_csv = dict_to_csv_string(measurement_json)

        save_metrics_to_local_file(siemplify, measurement_csv, folder_path)
        retention_files(siemplify, folder_path)

        email_msg = build_email_message(unix_ms_last_run_time, unix_ms_now)
        email_msg = email_msg.replace("\n", "<br>")
        send_mail(siemplify, email_msg, measurement_csv)

        siemplify.save_timestamp(new_timestamp=unix_ms_now)
        siemplify.LOGGER.info("Saved last_run_time:" + str(unix_ms_now))

        siemplify.LOGGER.info("--- Measurement Monitor started ---")

    except Exception as e:
        siemplify.LOGGER.error("Measurement Monitor Failed. Details: " + e.message)
        siemplify.LOGGER.info("===========================================================================")
        siemplify.LOGGER.exception(e)
        raise e

    if hasattr(siemplify.LOGGER, 'error_logged') and siemplify.LOGGER.error_logged:
        raise Exception("Error was logged during execution, check the logs")


if __name__ == "__main__":
    main()
