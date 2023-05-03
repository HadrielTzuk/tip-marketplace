from datamodels import *


class QRadarParser(object):
    def build_results(self, raw_json, method):
        return [getattr(self, method)(item_json) for item_json in (raw_json or [])]

    @staticmethod
    def build_siemplify_offense_object(offense_data):
        if offense_data.get("rules"):
            offense_data["rules"] = [rule.get("id") for rule in offense_data.get("rules", []) if rule.get("id")]

        if offense_data.get("log_sources"):
            offense_data["log_sources"] = [log_source.get("id") for log_source in offense_data.get("log_sources", []) if log_source.get("id")]

        return Offense(raw_data=offense_data, **offense_data)

    @staticmethod
    def build_siemplify_rule_object(rule_data):
        return Rule(rule_data, **rule_data)

    @staticmethod
    def build_siemplify_log_source_object(log_source_data):
        return LogSource(log_source_data, **log_source_data)

    @staticmethod
    def build_siemplify_event_object(event_data):
        return Event(
            raw_data=event_data,
            name=event_data.get("EventName"),
            rule_names=event_data.get("rulename_creEventList", []),
            qid=event_data.get("qid"),
            category=event_data.get("qid"),
            description=event_data.get("EventDescription"),
            credibility=event_data.get("credibility"),
            domain_id=event_data.get("domainID"),
            start_time=event_data.get("startTime"),
            end_time=event_data.get("endTime"),
            magnitude=event_data.get("magnitude"),
            relevance=event_data.get("relevance"),
            severity=event_data.get("severity"),
            device_product=event_data.get("deviceProduct")
        )

    @staticmethod
    def get_search_id_from_search_response(raw_data):
        return raw_data.get('search_id', '')

    @staticmethod
    def get_status_from_search_response(raw_data):
        return raw_data.get('status', '')

    def build_siemplify_flaw_object_list(self, raw_data):
        return [self.build_siemplify_flaw_object(raw_data=item) for item in raw_data.get('flows', [])]

    @staticmethod
    def build_siemplify_flaw_object(raw_data):
        return FlawObject(
            raw_data=raw_data
        )

    def build_siemplify_event_object_list(self, raw_data):
        return [self.build_siemplify_event_object(event_data=item) for item in raw_data.get('events', [])]

    def build_reasons_objects_list(self, raw_data):
        return [self.build_reason_object(item) for item in raw_data]

    def build_reason_object(self, raw_data):
        return Reason(
            raw_data=raw_data,
            reason_id=raw_data.get('id', ''),
            text=raw_data.get('text', '')
        )

    def build_reference_set_object(self, raw_data):
        return ReferenceSet(
            raw_data=raw_data,
            data=raw_data.get("data", [])
        )

    def build_reference_map_object(self, raw_data):
        return ReferenceMap(
            raw_data=raw_data,
            data=raw_data.get("data", {})
        )

    def build_reference_table_object(self, raw_data):
        return ReferenceTable(
            raw_data=raw_data,
            data=raw_data.get("data", {})
        )

    def build_list_of_mappings(self, raw_json):
        return [self.build_mitre_mapping_object(key=key, raw_data=value) for key, value in raw_json.items()]

    def build_mitre_mapping_object(self, key, raw_data):
        return MitreMapping(
            raw_data=raw_data,
            rule_name=key,
            id=raw_data.get("id"),
            mapping=raw_data.get("mapping", {})
        )

    @staticmethod
    def build_domain_obj_list(raw_data):
        if isinstance(raw_data, list):
            return [QRadarParser.build_domain_obj(raw_domain) for raw_domain in raw_data]
        return []

    @staticmethod
    def build_domain_obj(raw_data):
        return Domain(
            raw_data=raw_data,
            id=raw_data.get("id"),
            name=raw_data.get("name")
        )
