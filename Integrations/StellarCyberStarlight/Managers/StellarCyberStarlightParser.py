from datamodels import *


class StellarCyberStarlightParser(object):
    def build_all_hits(self, raw_data):
        return [self.build_hit_object(hit_json=hit_json) for hit_json in raw_data.get("hits", {}).get("hits", [])]

    def build_hit_object(self, hit_json):
        return Hit(
            raw_data=hit_json
        )

    def build_errors(self, raw_data):
        errors = raw_data.get("error", {}).get("root_cause", [])
        if errors:
            return "\n".join([self.build_error_object(error_json).message for error_json in errors])

    def build_error_object(self, raw_data):
        return ErrorObject(
            raw_data=raw_data,
            message=raw_data.get("reason")
        )

    def build_alert_object(self, alert_json):
        return Alert(
            raw_data=alert_json,
            id=alert_json.get('_id'),
            event_category=alert_json.get('_source', {}).get('event_category'),
            event_name=alert_json.get('_source', {}).get('event_name'),
            severity=alert_json.get('_source', {}).get('event_score'),
            timestamp=alert_json.get('_source', {}).get('timestamp')
        )
