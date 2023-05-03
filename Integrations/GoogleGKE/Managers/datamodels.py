import copy
from enum import Enum
from typing import Optional, List, Dict

from TIPCommon import dict_to_flat

from consts import (
    COMMA_SPACE
)


class FilterLogicParam(Enum):
    Equal = "Equal"
    Contains = "Contains"

    def __str__(self):
        return self.value


class BaseModel(object):
    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data

    def to_flat(self):
        return dict_to_flat(self.to_json())

    def to_table(self):
        return [self.to_csv()]

    def to_csv(self):
        return dict_to_flat(self.to_json())

    def is_empty(self):
        return not bool(self.raw_data)

    @classmethod
    def to_csv_table_value(cls, obj):
        """
        Parse dictionary to CSV table square value
        :param obj: {dict or list} Dictionary to parse
        :return: {str} Parsed values
        """
        if isinstance(obj, dict):
            return COMMA_SPACE.join([f"{key}:{value}" for key, value in obj.items()])
        if isinstance(obj, list):
            return COMMA_SPACE.join(obj)
        return obj


class KubeCluster(BaseModel):
    """
    Kubernetes Cluster data model
    """

    def __init__(self, raw_data: dict, cluster_id: Optional[str] = None, name: Optional[str] = None, description: Optional[str] = None,
                 cluster_network: Optional[str] = None, cluster_ipv4_cidr: Optional[str] = None, labels: Optional[List[str]] = None,
                 cluster_endpoint: Optional[str] = None, status: Optional[str] = None, location: Optional[str] = None, zone: Optional[str] = None,
                 initial_cluster_version: Optional[str] = None, current_master_version: Optional[str] = None,
                 current_node_version: Optional[str] = None, create_time: Optional[str] = None, label_fingerprint: Optional[str] = None):
        super(KubeCluster, self).__init__(raw_data=raw_data)
        self.cluster_id = cluster_id
        self.name = name
        self.description = description
        self.cluster_network = cluster_network
        self.cluster_ipv4_cidr = cluster_ipv4_cidr
        self.cluster_endpoint = cluster_endpoint
        self.status = status
        self.location = location
        self.zone = zone
        self.initial_cluster_version = initial_cluster_version
        self.current_master_version = current_master_version
        self.current_node_version = current_node_version
        self.create_time = create_time
        self.label_fingerprint = label_fingerprint
        self.labels = labels or {}

    @classmethod
    def get_name_attribute(cls):
        return "name"

    def to_csv(self):
        return {
            "ID": self.cluster_id,
            "Name": self.name,
            "Description": self.description,
            "Cluster Network": self.cluster_network,
            "Cluster Ipv4 CIDR": self.cluster_ipv4_cidr,
            "Labels": self.to_csv_table_value(self.labels),
            "Cluster Endpoint": self.cluster_endpoint,
            "Status": self.status,
            "Location": self.location,
            "Zone": self.zone,
            "Initial Cluster Version": self.initial_cluster_version,
            "Current Master Version": self.current_master_version,
            "Current Node Version": self.current_node_version,
            "Create Time": self.create_time
        }


class KubeClusterOperation(BaseModel):
    """
    Kubernetes Cluster Operation data model
    """

    def __init__(self, raw_data: dict, name=None, operation_type=None, status=None, zone=None, start_time=None, end_time=None, target_link=None,
                 self_link=None, cluster_name=None):
        super(KubeClusterOperation, self).__init__(raw_data)
        self.name = name
        self.zone = zone
        self.operation_type = operation_type
        self.status = status
        self.start_time = start_time
        self.end_time = end_time
        self.target_link = target_link
        self.self_link = self_link
        self.cluster_name = cluster_name

    @classmethod
    def get_name_attribute(cls):
        return "name"

    def to_csv(self):
        return {
            "Name": self.name,
            "Zone": self.zone,
            "Operation Type": self.operation_type,
            "Status": self.status,
            "Start Time": self.start_time,
            "End Time": self.end_time,
            "Target Link": self.target_link,
            "Self Link": self.self_link
        }

    def to_json(self):
        if self.cluster_name:
            data = copy.deepcopy(super().to_json())
            data.update({"cluster_name": self.cluster_name})
            return data
        return super().to_json()


class KubeClusterNodePool(BaseModel):
    """
    Kubernetes Cluster Node Pool data model
    """

    def __init__(self, raw_data: dict, name: Optional[str] = None, status: Optional[str] = None, version: Optional[str] = None,
                 machine_type: Optional[str] = None, tags: Optional[List[str]] = None, service_account: Optional[str] = None,
                 initial_node_count: Optional[int] = None, autoscaling: Optional[Dict] = None, max_pods_constraint: Optional[Dict] = None,
                 locations: Optional[List[str]] = None, auto_repair: Optional[bool] = None, auto_upgrade: Optional[bool] = None):
        super(KubeClusterNodePool, self).__init__(raw_data)
        self.name = name
        self.status = status
        self.version = version
        self.machine_type = machine_type
        self.service_account = service_account
        self.initial_node_count = initial_node_count
        self.auto_repair = auto_repair
        self.auto_upgrade = auto_upgrade
        self.autoscaling = autoscaling or {}
        self.max_pods_constraint = max_pods_constraint or {}
        self.tags = tags or []
        self.locations = locations or []

    @classmethod
    def get_name_attribute(cls):
        return "name"

    def to_csv(self):
        return {
            "Name": self.name,
            "Status": self.status,
            "Version": self.version,
            "Machine Type": self.machine_type,
            "Tags": self.to_csv_table_value(self.tags),
            "Service Account": self.service_account,
            "Initial Node Count": self.initial_node_count,
            "Autoscaling": self.to_csv_table_value(self.autoscaling),
            "Max Pods Constraint": self.to_csv_table_value(self.max_pods_constraint),
            "Locations": self.to_csv_table_value(self.locations)
        }
