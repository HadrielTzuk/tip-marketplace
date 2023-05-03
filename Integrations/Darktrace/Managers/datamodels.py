import copy
import uuid
from constants import DEVICE_VENDOR, DEVICE_PRODUCT, SEVERITY_MAP, EVENT_TYPES_NAMES
from TIPCommon import dict_to_flat, add_prefix_to_dict


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


class Alert(BaseModel):
    def __init__(self, raw_data, id, name, description, score, time):
        super(Alert, self).__init__(raw_data)
        self.uuid = uuid.uuid4()
        self.id = id
        self.name = name
        self.description = description
        self.score = score
        self.time = time
        self.events = []

    def get_alert_info(self, alert_info, environment_common, device_product_field):
        alert_info.environment = environment_common.get_environment(self.raw_data)
        alert_info.ticket_id = self.id
        alert_info.display_id = str(self.uuid)
        alert_info.name = self.name
        alert_info.description = self.description
        alert_info.device_vendor = DEVICE_VENDOR
        alert_info.device_product = self.raw_data.get(device_product_field) or DEVICE_PRODUCT
        alert_info.priority = self.get_siemplify_severity()
        alert_info.rule_generator = self.name
        alert_info.start_time = self.time
        alert_info.end_time = self.time
        alert_info.events = self.to_events()

        return alert_info

    def get_siemplify_severity(self):
        rounded_score = self.score * 100

        if 0 <= rounded_score <= SEVERITY_MAP["LOW"]:
            return SEVERITY_MAP["LOW"]
        elif SEVERITY_MAP["LOW"] < rounded_score <= SEVERITY_MAP["MEDIUM"]:
            return SEVERITY_MAP["MEDIUM"]
        elif SEVERITY_MAP["MEDIUM"] < rounded_score <= SEVERITY_MAP["HIGH"]:
            return SEVERITY_MAP["HIGH"]
        elif SEVERITY_MAP["HIGH"] < rounded_score <= SEVERITY_MAP["CRITICAL"]:
            return SEVERITY_MAP["CRITICAL"]

        return SEVERITY_MAP["INFO"]

    def set_events(self, events):
        self.events = events

    def to_events(self):
        events = [self.get_original_event()]
        events.extend([dict_to_flat(event.to_json()) for event in self.events])
        return events

    def get_original_event(self):
        original_event = self.to_json()
        original_event.pop("triggeredComponents")
        original_event["eventType"] = "modelbreach"
        return dict_to_flat(original_event)


class Device(BaseModel):
    def __init__(self, raw_data, mac_address, id, ip, did, os, hostname, type_label, device_label, typename,
                 first_seen, last_seen):
        super(Device, self).__init__(raw_data)
        self.mac_address = mac_address
        self.id = id
        self.ip = ip
        self.did = did
        self.os = os
        self.hostname = hostname
        self.type_label = type_label
        self.device_label = device_label
        self.typename = typename
        self.first_seen = first_seen
        self.last_seen = last_seen

    def to_table(self):
        table_data = {
            "macaddress": self.mac_address,
            "id": self.id,
            "ip": self.ip,
            "did": self.did,
            "os": self.os,
            "hostname": self.hostname,
            "typelabel": self.type_label,
            "devicelabel": self.device_label
        }

        return {key: value for key, value in table_data.items() if value}

    def to_similars_table(self):
        table_data = {
            "IP Address": self.ip,
            "Mac Address": self.mac_address,
            "OS": self.os,
            "Hostname": self.hostname,
            "Type": self.typename,
            "First Seen": self.first_seen,
            "Last Seen": self.last_seen
        }

        return {key: value for key, value in table_data.items() if value}

    def to_enrichment_data(self, prefix=None):
        data = dict_to_flat(self.to_table())
        return add_prefix_to_dict(data, prefix) if prefix else data

    def as_insight(self, identifier):
        return f"<p><strong>Endpoint: </strong>{identifier}</p>" \
               f"<table><tbody>" \
               f"<tr><td><strong>Hostname:</strong></td><td>{self.hostname}</td></tr>" \
               f"<tr><td><strong>IP Address:</strong></td><td>{self.ip}</td></tr>" \
               f"<tr><td><strong>Mac Address:</strong></td><td>{self.mac_address}</td></tr>" \
               f"<tr><td><strong>OS:</strong></td><td>{self.os}</td></tr>" \
               f"<tr><td><strong>Type:</strong></td><td>{self.type_label}</td></tr>" \
               f"<tr><td><strong>Label:</strong></td><td>{self.device_label}</td></tr>" \
               f"</tbody></table>"


class EndpointDetails(BaseModel):
    def __init__(self, raw_data, ip, country, asn, city, region, hostname, name, longitude, latitude, devices, ips,
                 locations):
        super(EndpointDetails, self).__init__(raw_data)
        self.ip = ip
        self.country = country
        self.asn = asn
        self.city = city
        self.region = region
        self.hostname = hostname
        self.name = name
        self.longitude = longitude
        self.latitude = latitude
        self.devices = devices
        self.ips = ips
        self.locations = locations

    def to_table(self):
        table_data = {
            "ip": self.ip,
            "country": self.country,
            "asn": self.asn,
            "city": self.city,
            "region": self.region,
            "hostname": self.hostname,
            "name": self.name,
            "longitude": self.longitude,
            "latitude": self.latitude,
            "count_related_devices": len(self.devices),
            "associated_ips": ",".join([ip.get("ip") for ip in self.ips]),
            "associated_countries": ",".join([location.get("country") for location in self.locations]),
        }

        return {key: value for key, value in table_data.items() if value}

    def to_enrichment_data(self, prefix=None):
        data = dict_to_flat(self.to_table())
        return add_prefix_to_dict(data, prefix) if prefix else data

    def to_csv(self):
        return [{
            "MacAddress": device.get("macaddress"),
            "Vendor": device.get("vendor"),
            "IP": device.get("ip"),
            "Hostname": device.get("hostname"),
            "OS": device.get("os"),
            "Type": device.get("typelabel")
        } for device in self.devices]


class ModelBreach(BaseModel):
    def __init__(self, raw_data, acknowledged):
        super(ModelBreach, self).__init__(raw_data)
        self.acknowledged = acknowledged


class Event(BaseModel):
    def __init__(self, raw_data):
        super(Event, self).__init__(raw_data)

    def to_table(self, event_type):
        if event_type == EVENT_TYPES_NAMES["connection"] \
                or event_type == EVENT_TYPES_NAMES["unusualconnection"] \
                or event_type == EVENT_TYPES_NAMES["newconnection"]:
            table_data = {
                "Direction": self.raw_data.get("direction"),
                "Source Port": self.raw_data.get("sourcePort"),
                "Destination Port": self.raw_data.get("destinationPort"),
                "Protocol": self.raw_data.get("protocol"),
                "Application": self.raw_data.get("applicationprotocol"),
                "Time": self.raw_data.get("time"),
                "Destination": self.raw_data.get("destination"),
                "Status": self.raw_data.get("status")
            }

            if event_type == EVENT_TYPES_NAMES["unusualconnection"] or event_type == EVENT_TYPES_NAMES["newconnection"]:
                table_data["Info"] = self.raw_data.get("info")

            return table_data

        if event_type == EVENT_TYPES_NAMES["notice"]:
            return {
                "Direction": self.raw_data.get("direction"),
                "Destination Port": self.raw_data.get("destinationPort"),
                "Type": self.raw_data.get("type"),
                "Time": self.raw_data.get("time"),
                "Destination": self.raw_data.get("destination"),
                "Message": self.raw_data.get("msg")
            }

        if event_type == EVENT_TYPES_NAMES["devicehistory"]:
            return {
                "Name": self.raw_data.get("name"),
                "Value": self.raw_data.get("value"),
                "Reason": self.raw_data.get("reason"),
                "Time": self.raw_data.get("time")
            }

        if event_type == EVENT_TYPES_NAMES["modelbreach"]:
            return {
                "Name": self.raw_data.get("name"),
                "State": self.raw_data.get("state"),
                "Score": self.raw_data.get("score"),
                "Time": self.raw_data.get("time"),
                "Active": self.raw_data.get("active")
            }


class ConnectionData(BaseModel):
    def __init__(self, raw_data):
        super(ConnectionData, self).__init__(raw_data)

    def to_json(self):
        data = copy.deepcopy(self.raw_data)

        for item in data.get("deviceInfo", []):
            item.pop("graphData", None)
            item.get("info", {}).pop("externalASNs", None)

        return data

    def to_table(self):
        rows = []
        external_domains = []

        for item in self.raw_data.get("deviceInfo", []):
            external_domains.extend(item.get("info", {}).get("externalDomains", []))

        rows.extend([{
            "Type": "External Domain",
            "Domain": external_domain.get("domain")
        }
            for external_domain in external_domains
        ])

        rows.extend([{
            "Type": "Internal Device",
            "IP Address": device.get("ip"),
            "Mac Address": device.get("macaddress")
        }
            for device in self.raw_data.get("devices", [])
        ])

        return rows


class SearchResult(BaseModel):
    def __init__(self, raw_data):
        super(SearchResult, self).__init__(raw_data)
