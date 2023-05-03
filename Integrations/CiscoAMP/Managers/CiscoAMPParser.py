from datamodels import Event


class CiscoAMPParser(object):
    """
    Cisco AMP Transformation Layer
    """

    @staticmethod
    def get_total_events(raw_data):
        return raw_data.get("metadata", {}).get("results", {}).get("total", 0)

    @staticmethod
    def get_prev_events_link(raw_data):
        return raw_data.get("metadata", {}).get("links", {}).get("prev")

    @staticmethod
    def build_event_obj(raw_data):
        return Event(
            raw_data=raw_data,
            severity=raw_data.get("severity"),
            event_id=raw_data.get("id"),
            event_type=raw_data.get("event_type"),
            start_date=raw_data.get("date"),
            timestamp=raw_data.get("timestamp"),
            timestamp_nanoseconds=raw_data.get("timestamp_nanoseconds")
        )

    @staticmethod
    def build_event_obj_list(raw_data):
        return [CiscoAMPParser.build_event_obj(raw_event) for raw_event in raw_data.get("data", [])]
