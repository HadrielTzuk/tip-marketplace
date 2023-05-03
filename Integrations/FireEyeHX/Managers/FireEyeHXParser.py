from datamodels import Indicator, Host, Alert, FileAcquisition, GroupAlerts, Ack, Group
from copy import deepcopy


class FireEyeHXParser(object):
    """
    FireEye HX Transformation Layer.
    """
    @staticmethod
    def build_siemplify_indicator_obj(indicator_data):
        return Indicator(raw_data=indicator_data, **indicator_data)

    @staticmethod
    def build_siemplify_host_obj(host_data):
        return Host(raw_data=host_data, **host_data)

    @staticmethod
    def build_siemplify_alert_obj(alert_data):
        return Alert(raw_data=alert_data, **alert_data)

    @staticmethod
    def build_siemplify_file_acquisition_obj(file_acquisition_data):
        return FileAcquisition(raw_data=file_acquisition_data, **file_acquisition_data)

    @staticmethod
    def build_siemplify_group_alert_obj(group_alert_data):
        return GroupAlerts(raw_data=group_alert_data,
                           id = group_alert_data.get(u"_id"),
                           indicator_display_name = group_alert_data.get(u"indicator", {}).get(u"display_name") if
                           group_alert_data.get(u"indicator", {}) else "",
                           event_at = group_alert_data.get(u"event_at"),
                           matched_at = group_alert_data.get(u"matched_at"),
                           reported_at = group_alert_data.get(u"reported_at"),
                           event_type = group_alert_data.get(u"event_type"),
                           source = group_alert_data.get(u"source")
                           )
    @staticmethod
    def build_siemplify_ack_obj(ack_data):
        return Ack(raw_data=ack_data,
                    total = ack_data.get(u"total"),
                    entiries_ids = [ ack.get("_id")  for ack in ack_data.get(u"entries",{})]
                    )

    @staticmethod
    def build_siemplify_group_obj(group_data):
        return Group(
                    raw_data=group_data,
                    assessment=group_data.get(u"assessment"),
                    alert_group_id=group_data.get(u"_id"),
                    first_event=group_data.get(u"first_event_at"),
                    last_event=group_data.get(u"last_event_at"),
                    ack=group_data.get(u"acknowledgement", {}).get(u"acknowledged"),
                    last_event_id=group_data.get(u"last_alert", {}).get(u"_id"),
                    events_count=group_data.get(u"stats", {}).get(u"events"),
                    detected_by=group_data.get(u"grouped_by", {}).get(u"detected_by")
                    )
