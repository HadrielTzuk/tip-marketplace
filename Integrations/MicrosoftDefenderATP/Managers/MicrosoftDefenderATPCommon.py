import datetime
from SiemplifyUtils import utc_now

IDS_HOURS_LIMIT = 72


class MicrosoftDefenderATPCommon(object):
    def __init__(self, siemplify_logger):
        self.siemplify_logger = siemplify_logger

    @staticmethod
    def validate_timestamp(last_run_timestamp, offset_in_hours):
        """
        Validate timestamp in range
        :param last_run_timestamp: {datetime} last run timestamp
        :param offset_in_hours: {datetime} last run timestamp
        :return: {datetime} if first run, return current time minus offset time, else return timestamp from file
        """
        current_time = utc_now()
        # Check if first run
        if current_time - last_run_timestamp > datetime.timedelta(hours=offset_in_hours):
            return current_time - datetime.timedelta(hours=offset_in_hours)
        else:
            return last_run_timestamp
