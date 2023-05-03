import uuid
import copy
from TIPCommon import dict_to_flat, add_prefix_to_dict
from constants import DEVICE_VENDOR, DEVICE_PRODUCT, SEVERITY_MAP, DEFAULT_RULE_GEN
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


class Message(BaseModel):
    def __init__(self, raw_data, tracking_id, status, received, route, info, message_details=None):
        super(Message, self).__init__(raw_data)
        self.uuid = str(uuid.uuid4())
        self.tracking_id = tracking_id
        self.status = status
        self.received = received
        self.route = route
        self.info = info
        self.message_details = message_details

    # Added for filter_old_alerts to be able to retrieve id directly from Message object
    @property
    def message_id(self):
        if not self.message_details:
            raise Exception("Fetch message details first to get message id")
        return self.message_details.message_id

    def __hash__(self):
        return hash(self.message_id)

    def __eq__(self, other):
        return self.message_id == other.message_id

    def get_alert_info(self, alert_info, environment_common, device_product_field):
        alert_info.environment = environment_common.get_environment(dict_to_flat(self.to_json()))
        alert_info.ticket_id = self.message_id
        alert_info.display_id = self.uuid
        alert_info.name = f"{self.status.capitalize()} Message"
        alert_info.reason = self.message_details.reason
        alert_info.description = self.message_details.queue_detail_status
        alert_info.device_vendor = DEVICE_VENDOR
        alert_info.device_product = self.raw_data.get(device_product_field) or DEVICE_PRODUCT
        alert_info.priority = self.get_severity()
        alert_info.rule_generator = self.message_details.reason or DEFAULT_RULE_GEN
        alert_info.end_time = alert_info.start_time = convert_string_to_unix_time(self.received)
        alert_info.events = self.message_details.to_events(received_time=self.received)

        return alert_info

    def get_severity(self):
        return SEVERITY_MAP.get(self.message_details.risk, -1)


class MessageDetails(BaseModel):
    def __init__(self, raw_data, message_id, tracking_id, reason, risk,
                 queue_detail_status, transmission_components, components):
        super(MessageDetails, self).__init__(raw_data)
        self.tracking_id = tracking_id
        self.message_id = message_id
        self.reason = reason
        self.risk = risk
        self.queue_detail_status = queue_detail_status
        self.transmission_components = transmission_components
        self.components = components

    def to_events(self, received_time):
        events = self.get_original_events()
        for comp in self.transmission_components:
            comp['received_time'] = received_time
            comp['event_type'] = comp.get('fileType', "").replace(" ", "")
            events.append(dict_to_flat(comp))

        for comp in self.components:
            comp['received_time'] = received_time
            comp['event_type'] = comp.get('type', "").replace(" ", "")
            events.append(dict_to_flat(comp))

        if not events:
            events.append(dict_to_flat(self.to_json()))

        return events

    def get_original_events(self):
        original_event = copy.deepcopy(self.to_json())
        delivered_message = original_event.pop("deliveredMessage", None)
        merged_events = []
        if delivered_message:
            for key, value in delivered_message.items():
                event_data = copy.deepcopy(original_event)
                event_data['deliveredMessage'] = value
                event_data['deliveredMessage']["recipient"] = key
                event_data['event_type'] = "Message"
                merged_events.append(dict_to_flat(event_data))

        return merged_events

