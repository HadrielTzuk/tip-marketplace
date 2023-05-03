from datamodels import *


class VectraParser(object):
    def build_endpoint_object(self, endpoint_json):
        return Endpoint(
                    raw_data=endpoint_json,
                    endpoint_id=endpoint_json.get(u"id"),
                    name=endpoint_json.get(u"name"),
                    state=endpoint_json.get(u"state"),
                    threat=endpoint_json.get(u"threat"),
                    certainty=endpoint_json.get(u"certainty"),
                    ip=endpoint_json.get(u"last_source"),
                    tags=endpoint_json.get(u"tags", []),
                    note=endpoint_json.get(u"note"),
                    url=endpoint_json.get(u"url"),
                    last_modified=endpoint_json.get(u"last_modified"),
                    groups=endpoint_json.get(u"groups", []),
                    is_key_asset=endpoint_json.get(u"is_key_asset"),
                    has_active_traffic=endpoint_json.get(u"has_active_traffic"),
                    is_targeting_key_asset=endpoint_json.get(u"is_targeting_key_asset"),
                    privilege_level=endpoint_json.get(u"privilege_level"),
                    previous_ip=endpoint_json.get(u"previous_ips", [])
        )

    def build_detection_object(self, detection_json):
        return Detection(
                    raw_data=detection_json,
                    detection_id=detection_json.get(u'id'),
                    name=detection_json.get(u'detection'),
                    tags=detection_json.get(u'tags'),
                    sensor_name=detection_json.get(u'sensor_name'),
                    priority=detection_json.get(u'threat'),
                    category=detection_json.get(u'category'),
                    first_timestamp=detection_json.get(u'first_timestamp'),
                    last_timestamp=detection_json.get(u'last_timestamp'),
                    grouped_details=detection_json.get(u'grouped_details'),
                    detection_category=detection_json.get(u'detection_category'),
                    detection_type=detection_json.get(u'detection_type'),
                    certainty=detection_json.get(u'certainty'),
                    threat=detection_json.get(u'threat')
        )

    def build_triage_rule_object(self, triage_rule_json):
        return TriageRule(
            raw_data=triage_rule_json,
            triage_id=triage_rule_json.get(u'id'),
            enabled=triage_rule_json.get(u'enabled'),
            detection_category=triage_rule_json.get(u'detection_category'),
            triage_category=triage_rule_json.get(u'triage_category'),
            detection=triage_rule_json.get(u'detection'),
            whitelist=triage_rule_json.get(u'is_whitelist'),
            priority=triage_rule_json.get(u'priority'),
            created_at=triage_rule_json.get(u'created_timestamp'),
            description=triage_rule_json.get(u'description')
        )
