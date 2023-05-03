from datamodels import *


class Site24x7Parser:
    def build_alert_logs_list(self, raw_data):
        return [self.build_alert_log_object(raw_data=alert_log) for alert_log in raw_data.get("data", [])]

    def build_alert_log_object(self, raw_data):
        return AlertLog(
            raw_data=raw_data,
            msg=raw_data.get("msg"),
            sent_time=raw_data.get("sent_time"),
            alert_type=raw_data.get("alert_type")
        )

    def build_monitors_list(self, raw_data):
        return [self.build_monitor_object(raw_data=monitor) for monitor in raw_data.get("data", [])]

    def build_monitor_object(self, raw_data):
        return Monitor(
            raw_data=raw_data,
            display_name=raw_data.get("display_name")
        )
