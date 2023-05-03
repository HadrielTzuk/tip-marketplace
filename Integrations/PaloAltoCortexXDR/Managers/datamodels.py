from abc import ABCMeta, abstractmethod

from SiemplifyUtils import dict_to_flat, add_prefix_to_dict

PREFIX = u"PaloAltoCortexXDR"


class AbstractData(object):
    """
    Abstract Data Model for others Data Models
    """
    __metaclass__ = ABCMeta

    def to_csv(self):
        return dict_to_flat(self.to_json())

    @abstractmethod
    def to_json(self):
        pass

    def as_enrichment_data(self):
        return add_prefix_to_dict(self.to_csv(), PREFIX)


class Endpoint(AbstractData):
    def __init__(self, raw_data, endpoint_id=None, endpoint_name=None, endpoint_type=None, endpoint_status=None,
                 os_type=None, ip=None, users=None, domain=None, first_seen=None, last_seen=None,
                 endpoint_version=None, is_isolated=None, group_name=None, **kwargs):
        self.raw_data = raw_data
        self.endpoint_id = endpoint_id
        self.endpoint_name = endpoint_name
        self.endpoint_type = endpoint_type
        self.endpoint_status = endpoint_status
        self.os_type = os_type
        self.ip = ip
        self.users = users
        self.domain = domain
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.endpoint_version = endpoint_version
        self.is_isolated = is_isolated
        self.group_name = group_name

    def as_csv(self):
        return {
            u"ID": self.endpoint_id,
            u"Name": self.endpoint_name,
            u"Type": self.endpoint_type,
            u"Status": self.endpoint_status,
            u"OS": self.os_type,
            u"IP Address": self.ip,
            u"Users": u", ".join(self.users),
            u"Domain": self.domain,
            u"First Seen": self.first_seen,
            u"Last Seen": self.last_seen,
            u"Endpoint Version": self.endpoint_version,
            u"Is Isolated": self.is_isolated,
            u"Group name": self.group_name,
        }

    def to_json(self):
        return self.raw_data

    def as_enrichment_data(self):
        return dict_to_flat(self.as_csv())


class DeviceViolation(AbstractData):
    def __init__(self, raw_data, violation_id=None, hostname=None, username=None, ip=None, timestamp=None,
                 type=None, vendor=None, product=None, serial=None, endpoint_id=None, **kwargs):
        self.raw_data = raw_data
        self.violation_id = violation_id
        self.hostname = hostname
        self.username = username
        self.ip = ip
        self.timestamp = timestamp
        self.type = type
        self.vendor = vendor
        self.product = product
        self.serial = serial
        self.endpoint_id = endpoint_id

    def to_csv(self):
        return {
            u"ID": self.violation_id,
            u"Hostname": self.hostname,
            u"Username": self.username,
            u"IP Address": self.ip,
            u"Type": self.type,
            u"Timestamp": self.timestamp,
            u"Vendor": self.vendor,
            u"Product": self.product,
            u"Serial": self.serial,
            u"Endpoint ID": self.endpoint_id
        }

    def to_json(self):
        return self.raw_data

    def as_enrichment_data(self):
        return dict_to_flat(self.to_csv())


class AgentReport(AbstractData):
    def __init__(self, raw_data, TIMESTAMP=None, RECEIVEDTIME=None, ENDPOINTID=None, ENDPOINTNAME=None,
                 DOMAIN=None, TRAPSVERSION=None, CATEGORY=None, TYPE=None, SUBTYPE=None, RESULT=None,
                 REASON=None, DESCRIPTION=None, **kwargs):
        self.raw_data = raw_data
        self.timestamp = TIMESTAMP
        self.received_time = RECEIVEDTIME
        self.endpoint_id = ENDPOINTID
        self.endpoint_name = ENDPOINTNAME
        self.domain = DOMAIN
        self.traps_version = TRAPSVERSION
        self.category = CATEGORY
        self.type = TYPE
        self.sub_type = SUBTYPE
        self.result = RESULT
        self.reason = REASON
        self.description = DESCRIPTION

    def as_csv(self):
        return {
            u"Timestamp": self.timestamp,
            u"Received Time": self.received_time,
            u"Endpoint ID": self.endpoint_id,
            u"Endpoint Name": self.endpoint_name,
            u"Domain": self.domain,
            u"TRAPS Version": self.traps_version,
            u"Category": self.category,
            u"Type": self.type,
            u"Subtype": self.sub_type,
            u"Result": self.result,
            u"Reason": self.reason,
            u"Description": self.description
        }

    def to_json(self):
        return self.raw_data

    def as_enrichment_data(self):
        return dict_to_flat(self.as_csv())
