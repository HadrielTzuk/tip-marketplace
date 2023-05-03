import uuid
from TIPCommon import dict_to_flat, add_prefix_to_dict, flat_dict_to_csv
from EnvironmentCommon import EnvironmentHandle
from SiemplifyConnectorsDataModel import AlertInfo

from StellarCyberStarlightConstants import (
    DEVICE_VENDOR,
    DEVICE_PRODUCT
)


class BaseModel(object):
    """
    Base model for inheritance
    """

    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data


class Hit(BaseModel):
    def __init__(self, raw_data):
        super(Hit, self).__init__(raw_data)


class ErrorObject(BaseModel):
    def __init__(self, raw_data, message):
        super(ErrorObject, self).__init__(raw_data)
        self.message = message


class Alert(BaseModel):
    def __init__(self, raw_data, id, event_category, event_name, severity, timestamp):
        super(Alert, self).__init__(raw_data)
        self.id = id
        self.event_category = event_category
        self.event_name = event_name
        self.severity = severity
        self.timestamp = timestamp
        self.name = "{}: {}".format(event_category.capitalize() if event_category else '', event_name)

    @property
    def priority(self):
        """
        Converts API severity format to SIEM priority
        @return: SIEM priority
        """
        if self.severity >= 100:
            return 100
        elif self.severity >= 80:
            return 80
        elif self.severity >= 60:
            return 60
        elif self.severity >= 40:
            return 40
        else:
            return -1

    def to_alert_info(self, environment):
        # type: (EnvironmentHandle) -> AlertInfo
        """
        Creates Siemplify Alert Info based on Indicator information
        @param environment: EnvironmentHandle object
        @return: Alert Info object
        """
        alert_info = AlertInfo()
        alert_info.ticket_id = self.id
        alert_info.display_id = str(uuid.uuid4())
        alert_info.name = self.name
        alert_info.device_vendor = DEVICE_VENDOR
        alert_info.device_product = DEVICE_PRODUCT
        alert_info.priority = self.priority
        alert_info.rule_generator = "{}:{}".format(self.event_category, self.event_name)
        alert_info.start_time = self.timestamp
        alert_info.end_time = self.timestamp
        alert_info.events = [self.to_event()]
        alert_info.environment = environment.get_environment(self.raw_data)

        return alert_info

    def to_event(self):
        return dict_to_flat(self.raw_data)
