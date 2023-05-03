from SiemplifyUtils import output_handler
# Imports.
from SiemplifyJob import SiemplifyJob
import SiemplifyUtils
import json
from utils import send_notification
from consts import SDK_JOB_CONNECTORS_ALERT_DIGESTION_ERRORS as NOTIFICATION_ID

# Consts.

# Providers and strings.
COMPONENT_NAME = "Connectors"  # Component name to fetch the error for.
COMPONENT_DISPLAY_NAME = "Alert Digestion Process - Connectors"
MONITORING_PROVIDER = 'Siemplify'
ATTACHMENT_FILE_NAME = "Top100ConnectorsErrors.txt"

# Messages.
MAIL_SUBJECT_PATTERN = 'Mail From Siemplify: Detected errors in component - {0}'.format(COMPONENT_DISPLAY_NAME)


def send_mail(siemplify, mail_message, log_errors):
    try:
        if (log_errors):
            attachment_string = json.dumps(log_errors, sort_keys=True, indent=4, separators=(',', ': '))
        else:
            attachment_string = ""

        recipients = siemplify.get_configuration(MONITORING_PROVIDER).get('Recipients').split(",")
        siemplify.send_mail(MAIL_SUBJECT_PATTERN, mail_message, recipients, ATTACHMENT_FILE_NAME,
                            str(attachment_string))


    except Exception as e:
        siemplify.LOGGER.warn(e)



@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = "Connectors Monitor"
    siemplify.LOGGER.info("----Connectors Monitor started---")

    try:
        # Settings and Configurations.
        # Elastic
        config = siemplify.get_configuration(MONITORING_PROVIDER)

        # Get Time Range.
        unix_ms_last_run_time = siemplify.fetch_timestamp()
        unix_ms_now = SiemplifyUtils.unix_now()

        # Message Date Display Format
        display_format = "%Y-%m-%d %H:%M:%S UTC"
        starttime_dt = SiemplifyUtils.convert_unixtime_to_datetime(unix_ms_last_run_time).strftime(display_format)
        endtime_dt = SiemplifyUtils.convert_unixtime_to_datetime(unix_ms_now).strftime(display_format)

        # Get Notifications.
        notification_objects = siemplify.get_faulted_connectors(unix_ms_last_run_time, unix_ms_now)

        if not notification_objects:
            siemplify.LOGGER.info("No error founds for component {}".format(COMPONENT_NAME))
        else:
            message = "Hello, Siemplify Connector Monitoring service has found errors in component {0} between {1} to {2}.".format(
                COMPONENT_DISPLAY_NAME, starttime_dt, endtime_dt)
            send_mail(siemplify, message, notification_objects)
            send_notification(siemplify, message, NOTIFICATION_ID)

        siemplify.save_timestamp(new_timestamp=unix_ms_now)
        siemplify.LOGGER.info("Saved last_run_time:" + str(unix_ms_now))

        siemplify.LOGGER.info("----Connectors Monitor finished---")

    except Exception as e:
        siemplify.LOGGER.error("Connectors Monitor ERROR. Details: " + e.message)
        siemplify.LOGGER.info("===========================================================================")
        siemplify.LOGGER.exception(e)
        raise e

    if (hasattr(siemplify.LOGGER, 'error_logged') and siemplify.LOGGER.error_logged):
        raise Exception("Error was logged during execution, check the logs")


if __name__ == "__main__":
    main()

