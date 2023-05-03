from SiemplifyUtils import output_handler
from SiemplifyJob import SiemplifyJob
import SiemplifyUtils
import json
from datetime import timedelta
from utils import send_notification
from consts import SDK_JOB_JOBS_ERRORS as NOTIFICATION_ID


COMPONENT_DISPLAY_NAME = "Jobs"
MONITORING_PROVIDER = 'Siemplify'

# Messages
MAIL_SUBJECT_PATTERN = 'Mail From Siemplify: Detected errors in component - {0}'.format(COMPONENT_DISPLAY_NAME)

# Configuration
NUMBER_OF_HOURS = 3


def send_mail(siemplify, mail_message, log_errors):
    try:
        if (log_errors):
            attachment_string = json.dumps(log_errors, sort_keys=True, indent=4, separators=(',', ': '))
        else:
            attachment_string = ""

        recipients = siemplify.get_configuration(MONITORING_PROVIDER).get('Recipients').split(",")
        siemplify.send_mail(MAIL_SUBJECT_PATTERN, mail_message, recipients, "TopJobsError.txt", str(attachment_string))


    except Exception as e:
        siemplify.LOGGER.warn(e)


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = "JobsMonitor"
    siemplify.LOGGER.info("----Jobs Monitor started---")

    try:
        # Get Time Range.
        search_from = SiemplifyUtils.utc_now() - timedelta(hours=NUMBER_OF_HOURS)
        unix_ms_search_from_time = SiemplifyUtils.convert_datetime_to_unix_time(search_from)
        unix_ms_now = SiemplifyUtils.unix_now()

        faulted_jobs_history = siemplify.get_faulted_jobs(NUMBER_OF_HOURS)

        if not faulted_jobs_history:
            siemplify.LOGGER.info("No error founds for component {}".format(COMPONENT_DISPLAY_NAME))
        else:
            display_format = "%Y-%m-%d %H:%M:%S UTC"
            starttime_dt = SiemplifyUtils.convert_unixtime_to_datetime(unix_ms_search_from_time).strftime(
                display_format)
            endtime_dt = SiemplifyUtils.convert_unixtime_to_datetime(unix_ms_now).strftime(display_format)
            msg = "Hello, Siemplify Monitoring service has found errors in component {0} between {1} to {2}.".format(
                COMPONENT_DISPLAY_NAME, starttime_dt, endtime_dt)
            send_mail(siemplify, msg, faulted_jobs_history)
            send_notification(siemplify, msg, NOTIFICATION_ID)

        siemplify.save_timestamp(new_timestamp=unix_ms_now)
        siemplify.LOGGER.info("Saved last_run_time:" + str(unix_ms_now))

        siemplify.LOGGER.info("----Jobs Monitor finished---")

    except Exception as e:
        siemplify.LOGGER.error("Jobs Monitor ERROR. Details: " + e.message)
        siemplify.LOGGER.info("===========================================================================")
        siemplify.LOGGER.exception(e)
        raise e

    if (hasattr(siemplify.LOGGER, 'error_logged') and siemplify.LOGGER.error_logged):
        raise Exception("Error was logged during execution, check the logs")


if __name__ == "__main__":
    main()