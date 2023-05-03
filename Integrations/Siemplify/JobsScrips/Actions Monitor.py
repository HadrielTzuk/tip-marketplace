from SiemplifyUtils import output_handler
# Imports.
from SiemplifyJob import SiemplifyJob
import SiemplifyUtils
import json
import os
import os.path
from datetime import timedelta
from utils import send_notification
from consts import SDK_JOB_ACTIONS_PLAYBOOK_ACTIONS_ERRORS as NOTIFICATION_ID

# Consts.
# Creds.


# Providers and strings.
COMPONENT_DISPLAY_NAME = "Playbook Actions"
MONITORING_PROVIDER = 'Siemplify'

PLAYBOOK_ERROR_LOOKBACK_MINUTES = 3 * 60
PLAYBOOK_ERROR_LOOKBACK_COUNT = 3

# Configuration
NUMBER_OF_HOURS = 3

# Messages.
MAIL_SUBJECT_PATTERN = 'Mail From Siemplify: Detected errors in component - {0}'.format(COMPONENT_DISPLAY_NAME)


def build_playbook_message(siemplify, faulted_jobs_history):
    custom_message = None

    if (faulted_jobs_history):
        siemplify.LOGGER.info("Fetched {} Playbooks errors".format(len(faulted_jobs_history)))

    errored_actions = check_playbooks_errors(siemplify, faulted_jobs_history)

    if (errored_actions):
        custom_message = "\nThe Following Playbook actions have failed more than {} times in the last {} minutes:\n\n {}".format(
            PLAYBOOK_ERROR_LOOKBACK_COUNT,
            PLAYBOOK_ERROR_LOOKBACK_MINUTES,
            "\n".join(errored_actions))

    return custom_message


def load_playbooks_errors_cache(siemplify):
    cache_file = os.path.join(siemplify.run_folder, "playbooks_error_cache.txt")
    cache = {}

    if (os.path.isfile(cache_file)):
        f = open(cache_file, "r")
        cache_json = f.read()
        cache = json.loads(cache_json)
        f.close()

    return cache


def check_playbooks_errors(siemplify, faulted_jobs_history):
    failed_action_names = []
    cache = load_playbooks_errors_cache(siemplify)
    cache = clear_old_errors_from_cache(cache)

    for faulted_item in faulted_jobs_history:
        action_name = None
        if (faulted_item['name']):
            action_name = faulted_item['name']

        timestamp = SiemplifyUtils.unix_now()

        if (faulted_item['creation_time']):
            timestamp_str = faulted_item['creation_time']
            timestamp_dt = SiemplifyUtils.convert_string_to_datetime(timestamp_str, "UTC")
            timestamp = SiemplifyUtils.convert_datetime_to_unix_time(timestamp_dt)

        add_action_name_to_cache(cache, action_name, timestamp)

    failed_action_names = check_for_max_allowed_errors_and_clean(siemplify, cache)

    save_playbooks_errors_cache(siemplify, cache)

    return failed_action_names


#
# Cacheditems[]
#   ActionName, times[]
#                  longs
#

def clear_old_errors_from_cache(cache):
    oldest_allowed_time = SiemplifyUtils.unix_now() - (PLAYBOOK_ERROR_LOOKBACK_MINUTES * 60 * 1000)

    for action_name in cache:
        allowed_times = []
        for time in cache[action_name]:
            if long(time) > oldest_allowed_time:
                allowed_times.append(time)

        cache[action_name] = allowed_times

    return cache


def check_for_max_allowed_errors_and_clean(siemplify, cache):
    errored_actions = []

    for action_name in cache:
        if (len(cache[action_name]) >= PLAYBOOK_ERROR_LOOKBACK_COUNT):
            errored_actions.append(action_name)

    for action_name in errored_actions:
        cache.pop(action_name)

    return errored_actions


def add_action_name_to_cache(cache, action_name, timestamp):
    if (action_name):
        if (action_name not in cache):
            cache[action_name] = []

        if (timestamp not in cache[action_name]):
            cache[action_name].append(timestamp)


def save_playbooks_errors_cache(siemplify, cache):
    cache_file = os.path.join(siemplify.run_folder, "playbooks_error_cache.txt")
    f = open(cache_file, "w")

    cache_json = json.dumps(cache)

    f.write(cache_json)
    f.close()


def send_mail(siemplify, mail_message, log_errors):
    try:
        if (log_errors):
            attachment_string = json.dumps(log_errors, sort_keys=True, indent=4, separators=(',', ': '))
        else:
            attachment_string = ""

        recipients = siemplify.get_configuration(MONITORING_PROVIDER).get('Recipients').split(",")
        siemplify.send_mail(MAIL_SUBJECT_PATTERN, mail_message, recipients, "TopActionError.txt",
                            str(attachment_string))


    except Exception as e:
        siemplify.LOGGER.warn(e)



@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = "ActionsMonitor"
    siemplify.LOGGER.info("----Playbooks Monitor started---")

    unix_ms_lastrun = SiemplifyUtils.unix_now()
    try:
        unix_ms_lastrun = unix_ms_last_run_time
    except Exception as ex:
        pass

    try:
        # Email

        # Get Time Range.
        search_from = SiemplifyUtils.utc_now() - timedelta(hours=NUMBER_OF_HOURS)
        unix_ms_search_from_time = SiemplifyUtils.convert_datetime_to_unix_time(search_from)
        unix_ms_now = SiemplifyUtils.unix_now()

        faulted_jobs_history = siemplify.get_failed_actions(NUMBER_OF_HOURS)

        if not faulted_jobs_history:
            siemplify.LOGGER.info("No {} errors found from {} to {}".format(COMPONENT_DISPLAY_NAME,
                                                                            SiemplifyUtils.convert_unixtime_to_datetime(
                                                                                unix_ms_lastrun),
                                                                            SiemplifyUtils.convert_unixtime_to_datetime(
                                                                                unix_ms_now)))

        else:
            display_format = "%Y-%m-%d %H:%M:%S UTC"
            starttime_dt = SiemplifyUtils.convert_unixtime_to_datetime(unix_ms_search_from_time).strftime(
                display_format)
            endtime_dt = SiemplifyUtils.convert_unixtime_to_datetime(unix_ms_now).strftime(display_format)
            case_ids = list({fault["case_id"] for fault in faulted_jobs_history if "case_id" in fault})

            msg = "Hello, Siemplify Monitoring service has found errors in component {0} between {1} to {2}. In Case " \
                  "IDs: {3}".format(COMPONENT_DISPLAY_NAME, starttime_dt, endtime_dt, case_ids)

            siemplify.LOGGER.info(msg)

            custom_message = build_playbook_message(siemplify, faulted_jobs_history)
            if custom_message:
                msg += "\n" + custom_message
                send_notification(siemplify, msg, NOTIFICATION_ID)
                msg = msg.replace("\n", "<br>")
                send_mail(siemplify, msg, faulted_jobs_history)

        siemplify.save_timestamp(new_timestamp=unix_ms_now)

        siemplify.LOGGER.info("----Playbooks Monitor finished---")

    except Exception as e:
        siemplify.LOGGER.error("Playbooks Monitor ERROR. Details: " + e.message)
        siemplify.LOGGER.info("===========================================================================")
        siemplify.LOGGER.exception(e)
        raise e

    if (hasattr(siemplify.LOGGER, 'error_logged') and siemplify.LOGGER.error_logged):
        raise Exception("Error was logged during execution, check the logs")


if __name__ == "__main__":
    main()
