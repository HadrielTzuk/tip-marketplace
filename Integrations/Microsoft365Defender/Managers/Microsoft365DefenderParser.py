from datamodels import *


class Microsoft365DefenderParser:
    def build_incident_object(self, raw_data, alerts = None):
        return Incident(
            raw_data=raw_data,
            incident_id=raw_data.get('incidentId'),
            incident_name=raw_data.get('incidentName'),
            severity=raw_data.get('severity'),
            classification=raw_data.get('classification'),
            created_time=raw_data.get('createdTime'),
            last_update_time=raw_data.get('lastUpdateTime'),
            alerts=alerts
        )

    @staticmethod
    def build_alert_object(raw_data):
        return Alert(
            raw_data=raw_data,
            alert_id=raw_data.get('alertId'),
            incident_id=raw_data.get('incidentId'),
            entities=raw_data.get('entities'),
            devices=raw_data.get('devices'),
            title=raw_data.get('title'),
            severity=raw_data.get('severity'),
            first_activity=raw_data.get('firstActivity'),
            last_activity=raw_data.get('lastActivity'),
            description=raw_data.get('description')
        )

    @staticmethod
    def build_alert_with_evidence_object(raw_data):
        return AlertWithEvidence(
            raw_data=raw_data,
            alert_id=raw_data.get('id'),
            incident_id=raw_data.get('incidentId'),
            title=raw_data.get('title'),
            severity=raw_data.get('severity'),
            first_activity=raw_data.get('firstActivityDateTime'),
            last_activity=raw_data.get('lastActivityDateTime'),
            description=raw_data.get('description'),
            evidences=raw_data.pop('evidence', [])
        )

    def build_device_objects(self, raw_data):
        return [self.build_device_object(item) for item in raw_data.get("Results", [])]

    @staticmethod
    def build_device_object(raw_data):
        return Device(
            raw_data=raw_data
        )
