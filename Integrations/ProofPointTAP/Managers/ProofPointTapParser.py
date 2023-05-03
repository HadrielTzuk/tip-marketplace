from datamodels import *


class ProofPointTapParser:
    def build_results(self, raw_json, method, data_key='data', pure_data=False, limit=None, **kwargs):
        return [getattr(self, method)(item_json, **kwargs) for item_json in (raw_json if pure_data else
                                                                             raw_json.get(data_key, []))[:limit]]

    def build_forensic_data_object(self, raw_data, filters, limit=None):
        raw_data = raw_data.get('reports', [])[0] if raw_data.get('reports', []) else []
        if filters:
            filtered_data = self._filter_results_by_type(raw_data.get('forensics', []), filters)
            raw_data.update({"forensics": filtered_data[:limit]})

        return ForensicObj(
            raw_data=raw_data,
            forensics=self.build_results(raw_data.get('forensics'), method='build_forensic_obj', pure_data=True) if
            raw_data.get('forensics') else []
        )

    def _filter_results_by_type(self, data, filters):
        results = []
        for item in data:
            if item.get('type', '') in filters:
                results.append(item)

        return results

    def build_campaign_obj(self, raw_data):
        return Campaign(raw_data=raw_data, **raw_data)

    def build_forensic_obj(self, raw_data):
        return Forensic(raw_data=raw_data, **raw_data)

    def build_decode_url(self, raw_data):
        return DecodedURL(raw_data=raw_data, **raw_data)
