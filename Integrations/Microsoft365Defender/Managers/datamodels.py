import uuid
import copy
from TIPCommon import dict_to_flat, add_prefix_to_dict
from constants import DEVICE_VENDOR, DEVICE_PRODUCT, SEVERITY_MAP, ENTITIES_KEY, DEVICES_KEY, DEFAULT_CLASSIFICATION
from SiemplifyUtils import convert_string_to_unix_time


class BaseModel:
    """
    Base model for inheritance
    """
    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data

    def to_csv(self):
        return dict_to_flat(self.to_json())

    def to_enrichment_data(self, prefix=None):
        data = dict_to_flat(self.raw_data)
        return add_prefix_to_dict(data, prefix) if prefix else data


class Device(BaseModel):
    def __init__(self, raw_data):
        super(Device, self).__init__(raw_data)


class BaseAlert(BaseModel):
    def __init__(self, raw_data, alert_id, incident_id, title, severity, first_activity,
                 last_activity, description):
        super(BaseAlert, self).__init__(raw_data)
        self.alert_id = alert_id
        self.incident_id = incident_id
        self.title = title
        self.severity = severity
        self.first_activity = first_activity
        self.last_activity = last_activity
        self.description = description


    def get_alert_info(self, alert_info, environment_common, incident_event):
        alert_info.environment = environment_common.get_environment(dict_to_flat(self.to_json()))
        alert_info.ticket_id = self.incident_id
        alert_info.display_id = self.alert_id
        alert_info.name = self.title
        alert_info.description = self.description
        alert_info.device_vendor = DEVICE_VENDOR
        alert_info.device_product = DEVICE_PRODUCT
        alert_info.priority = self.get_severity()
        alert_info.rule_generator = self.title
        alert_info.source_grouping_identifier = self.incident_id
        alert_info.start_time = convert_string_to_unix_time(self.first_activity)
        alert_info.end_time = convert_string_to_unix_time(self.last_activity)
        alert_info.events = self.create_events(incident_event)

        return alert_info

    def get_severity(self):
        return SEVERITY_MAP.get(self.severity, -1)

    def create_events(self, incident_event):
        raise NotImplemented


class Alert(BaseAlert):
    def __init__(self, raw_data, alert_id, incident_id, title, severity, first_activity,
                 last_activity, description, entities, devices):
        super(Alert, self).__init__(
            raw_data=raw_data,
            alert_id=alert_id,
            incident_id=incident_id,
            title=title,
            severity=severity,
            first_activity=first_activity,
            last_activity=last_activity,
            description=description
        )
        self.entities = entities
        self.devices = devices

    def create_events(self, incident_event):
        events = [incident_event]
        alert_data = copy.deepcopy(self.to_json())
        alert_data['event_type'] = 'Alert'
        entites = alert_data.pop(ENTITIES_KEY, None) or []
        devices = alert_data.pop(DEVICES_KEY, None) or []
        if len(entites) >= len(devices):
            for i, entity in enumerate(entites):
                alert_data[ENTITIES_KEY] = entity
                device = devices[i] if i < len(devices) else devices[0] if devices else None
                if device:
                    alert_data[DEVICES_KEY] = device
                events.append(dict_to_flat(alert_data))
        elif len(entites) < len(devices):
            for i, device in enumerate(devices):
                alert_data[DEVICES_KEY] = devices
                entity = entites[i] if i < len(entites) else entites[0] if entites else None
                if entity:
                    alert_data[ENTITIES_KEY] = entity
                events.append(dict_to_flat(alert_data))

        return events


class AlertWithEvidence(BaseAlert):
    def __init__(self, raw_data, alert_id, incident_id, title, severity, first_activity,
                 last_activity, description, evidences):
        super(AlertWithEvidence, self).__init__(
            raw_data=raw_data,
            alert_id=alert_id,
            incident_id=incident_id,
            title=title,
            severity=severity,
            first_activity=first_activity,
            last_activity=last_activity,
            description=description
        )
        self.evidences = evidences

    def create_events(self, incident_event):
        events = [incident_event]
        alert_data = copy.deepcopy(self.to_json())

        for evidence_data in self.evidences:
            evidence_data["event_type"] = "Evidence"
            evidence_data["alert_metadata"] = alert_data
            events.append(dict_to_flat(evidence_data))

        return events


class Incident(BaseModel):
    def __init__(self, raw_data, incident_id, incident_name, severity, classification, created_time, last_update_time, alerts):
        super(Incident, self).__init__(raw_data)
        self.uuid = uuid.uuid4()
        self.incident_id = incident_id
        self.incident_name = incident_name
        self.severity = severity
        self.classification = classification
        self.created_time = created_time
        self.last_update_time = last_update_time
        self.alerts = alerts

    def get_alert_info(self, alert_info, environment_common):
        alert_info.environment = environment_common.get_environment(dict_to_flat(self.to_json()))
        alert_info.ticket_id = self.incident_id
        alert_info.display_id = self.incident_id
        alert_info.name = self.incident_name
        alert_info.device_vendor = DEVICE_VENDOR
        alert_info.device_product = DEVICE_PRODUCT
        alert_info.priority = self.get_severity()
        alert_info.rule_generator = self.incident_name
        alert_info.source_grouping_identifier = self.incident_id
        alert_info.end_time = alert_info.start_time = convert_string_to_unix_time(self.created_time)
        alert_info.events = [self.as_event()]

        return alert_info

    def get_severity(self):
        return SEVERITY_MAP.get(self.severity, -1)

    def as_event(self):
        event_data = copy.deepcopy(self.raw_data)
        event_data.pop('alerts', None)
        event_data['event_type'] = 'Incident'
        return dict_to_flat(event_data)
