import copy
from typing import Dict, List, Optional

from utils import (prepare_instance_network_interfaces_to_enrich,
                   prepare_instance_service_account_to_enrich,
                   extract_name_from_address,
                   extract_tags_values,
                   fix_json_results)


class BaseModel(object):
    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data

    def is_empty(self):
        return not bool(self.raw_data)


class Instance(BaseModel):
    def __init__(self, raw_data,
                 id: str = None,
                 creationTimestamp: str = None,
                 name: str = None,
                 description: str = None,
                 status: str = None,
                 tags: dict = None,
                 type: str = None,
                 labels: Optional[Dict] = None,
                 labelFingerprint: Optional[str] = None,
                 network_interfaces=None,
                 machineType: str = None,
                 zone: str = None,
                 canIpForward: bool = None,
                 metadata: Dict = None,
                 serviceAccounts: List = None,
                 selfLink: str = None,
                 lastStartTimestamp: str = None,
                 lastStopTimestamp: str = None,
                 **kwargs):
        super(Instance, self).__init__(raw_data)
        self.id = id
        self.creationTimestamp = creationTimestamp
        self.name = name
        self.tags = tags or {}
        self.type = type
        self.description = description
        self.status = status
        self.labels = labels or {}
        self.label_fingerprint = labelFingerprint
        self.machine_type = machineType
        self.network_interfaces = network_interfaces
        self.zone = zone
        self.can_ip_forward = canIpForward
        self.metadata = metadata or {}
        self.service_accounts = serviceAccounts
        self.self_link = selfLink
        self.last_start_timestamp = lastStartTimestamp
        self.last_stop_timestamp = lastStopTimestamp

    def as_json(self) -> Dict:
        return fix_json_results(self.raw_data)

    def as_csv(self) -> Dict:
        return {
            "Instance Name": self.name,
            "Instance ID": self.id,
            "Instance Creation Time": self.creationTimestamp,
            "Instance Description": self.description,
            "Instance Type": extract_name_from_address(self.machine_type),
            "Instance Status": self.status,
            "Instance Labels": self.labels
        }

    def as_enrichment(self):
        enrichment_data = {
            'instance_id': self.id,
            'creation_timestamp': self.creationTimestamp,
            'instance_name': self.name,
            'description': self.description,
            'tags': ', '.join(extract_tags_values(self.tags)) if self.tags else None,
            'machine_type': extract_name_from_address(self.machine_type),
            'instance_status': self.status,
            'zone': extract_name_from_address(self.raw_data.get('zone', '')),
            'can_ip_forward': self.can_ip_forward,
            'metadata': ', '.join(self.metadata.values()) if self.metadata else None,
            'link_to_Google_Compute': self.self_link,
            'labels': ', '.join(self.labels.values()) if self.metadata else None,
            'instance_last_start_timestamp': self.last_start_timestamp,
            'instance_last_stop_timestamp': self.last_stop_timestamp
        }

        enrichment_data.update(prepare_instance_network_interfaces_to_enrich(self))
        enrichment_data.update(prepare_instance_service_account_to_enrich(self))

        return enrichment_data

    def as_enrichment_csv(self, enrichment_dict: Dict):
        return [{"key": key, "value": value} for key, value in enrichment_dict.items()]


class InstanceIAMPolicy(BaseModel):
    """
    Instance IAM Policy data model
    """

    def __init__(self, raw_data, etag: Optional[str] = None, **kwargs):
        super(InstanceIAMPolicy, self).__init__(raw_data)
        self.etag = etag


class OperationResource(BaseModel):
    """
    Operation Resource data model
    """

    def __init__(self, raw_data, zone: Optional[str] = None):
        super(OperationResource, self).__init__(raw_data)
        self.zone = zone

    def to_json(self):
        try:
            if self.zone:
                raw_data = copy.deepcopy(self.raw_data)
                raw_data.update({"zone": self.zone.rsplit("/", 1)[-1]})
                return raw_data
        except:
            pass
        return self.raw_data


class InstanceNetworkInterface(object):
    def __init__(self, raw_data,
                 network: str = None,
                 subnetwork: str = None,
                 networkIP: str = None,
                 name: str = None,
                 accessConfigs: List = None,
                 fingerprint: str = None,
                 kind: str = None,
                **kwargs):
        self.raw_data = raw_data
        self.network = network
        self.subnetwork = subnetwork
        self.networkIP = networkIP
        self.name = name
        self.accessConfigs = accessConfigs
        self.fingerprint = fingerprint
        self.kind = kind
