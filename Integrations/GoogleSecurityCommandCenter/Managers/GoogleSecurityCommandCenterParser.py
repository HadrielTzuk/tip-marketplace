from datamodels import *


class GoogleSecurityCommandCenterParser:
    def build_alerts_details_list(self, raw_data):
        return [self.build_alert_details_object(item) for item in raw_data.get("listFindingsResults", [])]

    def build_finding_details_list(self, raw_data):
        return [self.build_finding_details_object(item) for item in raw_data.get("listFindingsResults", [])]

    @staticmethod
    def build_alert_details_object(raw_data):
        alert_data = raw_data.get("finding") if raw_data.get("finding", {}) else raw_data
        resource_data = raw_data.get("resource") if raw_data.get("resource", {}) else raw_data
        return FindingAlert(
            raw_data=alert_data,
            resource_data=resource_data
        )

    @staticmethod
    def build_finding_details_object(raw_data):
        finding_data = raw_data.get("finding") if raw_data.get("finding", {}) else raw_data
        return FindingDetails(
            raw_data=raw_data,
            name=finding_data.get("name"),
            category=finding_data.get("category"),
            state=finding_data.get("state"),
            severity=finding_data.get("severity"),
            finding_class=finding_data.get("findingClass"),
            description=finding_data.get("description"),
            event_time=finding_data.get("eventTime"),
            cve_id=finding_data.get("vulnerability", {}).get('cve', {}).get('id'),
            recommendation=finding_data.get("sourceProperties", {}).get('Recommendation')
        )

    def build_asset_objects(self, raw_json):
        raw_json = raw_json.get("listAssetsResults", [])
        return [self.build_asset_object(raw_data) for raw_data in raw_json]

    def build_asset_object(self, raw_data):
        return Asset(
            raw_data=raw_data,
            asset_name=raw_data.get('asset', {}).get('securityCenterProperties', {}).get('resourceName', ''),
            resource_name=raw_data.get('asset', {}).get('securityCenterProperties', {}).get('resourceDisplayName', ''),
            resource_type=raw_data.get('asset', {}).get('securityCenterProperties', {}).get('resourceType', ''),
            create_time=raw_data.get('asset', {}).get('createTime', ''),
            update_time=raw_data.get('asset', {}).get('updateTime', ''),
            email=raw_data.get('asset', {}).get('resourceProperties', {}).get('email', ''),
            address=raw_data.get('asset', {}).get('resourceProperties', {}).get('address', '')
        )


