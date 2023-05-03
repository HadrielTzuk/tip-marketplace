from datamodels import *


class OrcaSecurityParser:
    def build_results(self, raw_json, method, data_key='data', pure_data=False, limit=None, **kwargs):
        return [getattr(self, method)(item_json, **kwargs) for item_json in (raw_json if pure_data else
                                                                             raw_json.get(data_key, []))[:limit]]

    def build_alert_objects(self, raw_data):
        return [self.build_alert_object(item) for item in raw_data.get("data", {})]

    @staticmethod
    def build_alert_object(raw_data):
        return Alert(
            raw_data=raw_data,
            alert_id=raw_data.get("state", {}).get("alert_id"),
            title=raw_data.get("data", {}).get("title"),
            details=raw_data.get("data", {}).get("details"),
            severity=raw_data.get("state", {}).get("severity"),
            created_at=raw_data.get("state", {}).get("created_at"),
            asset_name=raw_data.get("asset_name"),
            asset_type=raw_data.get("asset_type"),
            type_string=raw_data.get("type_string")
        )

    @staticmethod
    def build_alert_comment_object(raw_data):
        return AlertComment(
            raw_data=raw_data
        )

    def build_framework_objects(self, raw_data):
        return [self.build_framework_object(item) for item in raw_data.get("data", {}).get("frameworks", [])]

    @staticmethod
    def build_framework_object(raw_data):
        return Framework(
            raw_data=raw_data,
            display_name=raw_data.get("display_name"),
            description=raw_data.get("description"),
            avg_score_percent=raw_data.get("avg_score_percent"),
            test_results_fail=raw_data.get("test_results", {}).get("FAIL"),
            test_results_pass=raw_data.get("test_results", {}).get("PASS"),
            active=raw_data.get("active"),
        )

    @staticmethod
    def build_scan_status_object(raw_data):
        return ScanStatus(
            raw_data=raw_data,
            scan_id=raw_data.get("scan_unique_id"),
            status=raw_data.get("status")
        )

    @staticmethod
    def build_cve_object(raw_json):
        return CVE(raw_json, **raw_json)

    @staticmethod
    def build_asset_object(raw_json):
        return Asset(raw_json, **raw_json)