from SiemplifyUtils import output_handler
import calendar
from SiemplifyAction import *
import SiemplifyUtils
from time import daylight, altzone, timezone
import datetime
from pytz import timezone


class PermittedTime:
    def __init__(self, parameters, logger):
        self.LOGGER = logger
        self.start_time = self.get_time_from_string(parameters["Permitted Start Time"])
        self.end_time = self.get_time_from_string(parameters["Permitted End Time"])
        self.input_tz = parameters[
            "Input Timezone"]  # https://gist.github.com/heyalexej/8bf688fd67d7199be4a1682b3eec7568
        self.days = []
        if (parameters["Monday"].lower() == "true"):
            self.days.append(0)
        if (parameters["Tuesday"].lower() == "true"):
            self.days.append(1)
        if (parameters["Wednesday"].lower() == "true"):
            self.days.append(2)
        if (parameters["Thursday"].lower() == "true"):
            self.days.append(3)
        if (parameters["Friday"].lower() == "true"):
            self.days.append(4)
        if (parameters["Saturday"].lower() == "true"):
            self.days.append(5)
        if (parameters["Sunday"].lower() == "true"):
            self.days.append(6)

    def get_time_from_string(self, time_str):
        try:
            dt = datetime.datetime.strptime(time_str, "%H:%M:%S")
        except ValueError:
            dt = datetime.datetime.strptime(time_str, "%H:%M")

        return dt.time()

    def is_datetime_between_target_tz_time_values(self, aware_dt, start_time, end_time):
        target_tz_dt = SiemplifyUtils.convert_timezone(aware_dt, self.input_tz)
        # target_tz_dt = aware_dt.astimezone(timezone(self.input_tz))
        target_tz_time = target_tz_dt.time()

        is_permitted = (start_time <= target_tz_time and target_tz_time <= end_time)

        return is_permitted

    def __repr__(self):
        return "between %s - %s on %s" % (
            self.start_time, self.end_time, map(lambda d: calendar.day_name[d], self.days))


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "Permitted Alert Time"

    permitted_time = PermittedTime(siemplify.parameters, siemplify.LOGGER)
    if not siemplify.current_alert:
        siemplify.end("No alert selected", None)

    alert_start = siemplify.current_alert.start_time
    siemplify.LOGGER.info(
        "alert_name={} |  alert_time={} | start_time={} | end_time={}".format(siemplify.current_alert.name, alert_start,
                                                                              permitted_time.start_time,
                                                                              permitted_time.end_time))

    is_permitted = (permitted_time.is_datetime_between_target_tz_time_values(alert_start, permitted_time.start_time,
                                                                             permitted_time.end_time) and
                    alert_start.weekday() in permitted_time.days)

    siemplify.LOGGER.info("is_permitted: " + str(is_permitted))

    target_tz_alert_time = SiemplifyUtils.convert_timezone(siemplify.current_alert.start_time,
                                                           siemplify.parameters["Input Timezone"])
    alert_time_display_str = target_tz_alert_time.strftime("%Y %b %d %X")
    is_or_not_value = "" if is_permitted else "not "

    output_message = "Case Time of %s is %s within condition parameters of %s" % (
    alert_time_display_str, is_or_not_value, permitted_time)

    siemplify.end(output_message, str(is_permitted))


if __name__ == '__main__':
    main()
