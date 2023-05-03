from datamodels import *


class MandiantParser:
    def get_token(self, raw_json):
        return raw_json.get('access_token')

    def build_indicators_list(self, raw_data):
        return [self.build_indicator_obj(item) for item in raw_data.get("indicators", [])]

    def build_indicator_obj(self, raw_json):
        return Indicator(raw_json, **raw_json)

    def build_actor_obj(self, raw_json):
        return ThreatActor(raw_json, **raw_json)

    def build_vulnerability_obj(self, raw_json):
        return Vulnerability(raw_json, **raw_json)

    def build_malware_obj(self, raw_json):
        return Malware(raw_json, **raw_json)