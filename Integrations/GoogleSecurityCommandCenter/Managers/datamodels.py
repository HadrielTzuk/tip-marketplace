from TIPCommon import dict_to_flat, add_prefix_to_dict
from SiemplifyUtils import convert_string_to_unix_time
import json
import copy
from constants import GOOGLE_SERVICE_ACCOUNT_VALUE, GOOGLE_COMPUTE_ADDRESS_VALUE, GOOGLE_COMPUTE_INSTANCE_VALUE, \
    GOOGLE_CLOUD_STORAGE_VALUE, VULNERABILITY_CLASS, SEVERITY_MAPPING


class BaseModel:
    """
    Base model for inheritance
    """
    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data

    def to_table(self):
        return dict_to_flat(self.to_json())

    def to_enrichment_data(self, prefix=None):
        data = dict_to_flat(self.raw_data)
        return add_prefix_to_dict(data, prefix) if prefix else data


class FindingAlert(BaseModel):
    def __init__(self, raw_data, resource_data):
        super().__init__(raw_data)
        self._category = raw_data.get("category")
        self._name = raw_data.get("name")
        self._severity = raw_data.get("severity")

        self.id = self._name

        self.ticket_id = self._name
        self.display_id = f"GSCC_{self._name}"
        self.name = self._category
        self.description = raw_data.get("description")
        self.device_vendor = "Google Security Command Center"

        if self._severity == "SEVERITY_UNSPECIFIED":
            self.priority = "MEDIUM"
        else:
            self.priority = self._severity

        self.rule_generator = self._category
        self.source_grouping_identifier = self._category
        self.resource_data = dict(resource=resource_data)

        try:
            self.start_time = convert_string_to_unix_time(raw_data.get("eventTime"))
        except Exception:
            self.start_time = 1

        try:
            self.end_time = convert_string_to_unix_time(raw_data.get("eventTime"))
        except Exception:
            self.end_time = 1

    def as_event(self):
        event_data, resource_data = self.raw_data.copy(), self.resource_data.copy()
        event_data.update(resource_data)

        additional_key = {
            event_data["resource"]["type"]: resource_data["resource"].get("displayName", "")
        }
        event_data["resource"].update(additional_key)

        return dict_to_flat(event_data)

    def get_alert_info(self, alert_info, environment_common, device_product_field):
        alert_info.environment = environment_common.get_environment(dict_to_flat(self.as_event()))
        alert_info.ticket_id = self.ticket_id
        alert_info.display_id = self.display_id
        alert_info.name = self.name
        alert_info.description = self.description
        alert_info.device_vendor = self.device_vendor
        alert_info.device_product = self.raw_data.get(device_product_field, "Google Security Command Center")
        alert_info.priority = SEVERITY_MAPPING.get(self.priority, -1)
        alert_info.rule_generator = self.rule_generator
        alert_info.source_grouping_identifier = self.source_grouping_identifier
        alert_info.end_time, alert_info.start_time = self.end_time, self.start_time
        alert_info.events = [self.as_event()]

        return alert_info


class FindingDetails(BaseModel):
    def __init__(self, raw_data, name, category, state, severity, finding_class, description, event_time, cve_id,
                 recommendation):
        super(FindingDetails, self).__init__(raw_data)
        self.name = name
        self.category = category
        self.state = state
        self.severity = severity
        self.finding_class = finding_class
        self.description = description
        self.event_time = event_time
        self.cve_id = cve_id
        self.recommendation = recommendation

    def get_severity(self):
        return SEVERITY_MAPPING.get(self.severity, -1)

    def as_json(self):
        json_data = copy.deepcopy(self.raw_data)
        json_data["finding_name"] = self.name
        return json_data

    def to_table(self):
        return dict_to_flat({
            "Category": self.category,
            "State": self.state,
            "Severity": self.severity,
            "Type": self.finding_class
        })

    def as_vulnerability_json(self):
        return self.raw_data.get("finding", {})

    def to_vulnerability_table(self):
        if self.finding_class == VULNERABILITY_CLASS:
            return dict_to_flat({
                "Category": self.category,
                "Description": self.description,
                "Severity": self.severity,
                "Event Time": self.event_time,
                "CVE": self.cve_id
            })

        return dict_to_flat({
            "Category": self.category,
            "Description": self.description,
            "Severity": self.severity,
            "Event Time": self.event_time,
            "Recommendation": self.recommendation
        })


class Asset(BaseModel):
    def __init__(self, raw_data, asset_name, resource_name, resource_type, create_time, update_time, email, address):
        super().__init__(raw_data)
        self.raw_data, self.resource_owners = self.__modify_and_get_data()
        self.asset_name = asset_name
        self.resource_name = resource_name
        self.resource_type = resource_type
        self.resource_properties = self.raw_data.get('asset', {}).get('resourceProperties', {})
        self.create_time = create_time
        self.update_time = update_time
        self.email = email
        self.address = address

    def get_user_friendly_name(self):
        if self.resource_type == GOOGLE_SERVICE_ACCOUNT_VALUE:
            return self.email
        elif self.resource_type == GOOGLE_COMPUTE_ADDRESS_VALUE:
            return self.address
        else:
            return self.resource_name

    def __modify_and_get_data(self):
        modify_data = copy.deepcopy(self.raw_data)
        for key, value in self.raw_data.get('asset').items():
            if isinstance(value, dict):
                for subkey, subvalue in self.raw_data.get('asset')[key].items():
                    try:
                        item = json.loads(subvalue)
                        modify_data.get('asset')[key].update({subkey: item})
                    except Exception as e:
                        print(e)
            try:
                item_json = json.loads(value)
                modify_data.get('asset').update({key: item_json})
            except Exception as e:
                print(e)

        resource_owners = modify_data.get('asset', {}).get('securityCenterProperties', {}).get('resourceOwners', [])
        resource_owners = self.update_resource_owners(resource_owners)
        modify_data.get('asset').get('securityCenterProperties', {}).update({
            "resourceOwners": resource_owners
        })
        return modify_data, resource_owners

    def update_resource_owners(self, data):
        resource_owners = {}
        for owner in data:
            key, value = owner.split(':')
            if not resource_owners.get(key):
                resource_owners[key] = []
            resource_owners[key].append(value)

        return resource_owners

    def to_json(self):
        return self.raw_data

    def to_table(self):
        if self.resource_type == GOOGLE_SERVICE_ACCOUNT_VALUE:
            data = {
                'name': self.resource_name,
                'type': self.resource_type,
                'create_time': self.create_time,
                'update_time': self.update_time,
                'display_name': self.resource_properties.get('displayName', ''),
                'disabled': self.resource_properties.get('disabled', '')
            }
            return self.fill_resource_owner_keys(data)

        elif self.resource_type == GOOGLE_CLOUD_STORAGE_VALUE:
            roles = [item.get('role') for item in self.raw_data.get('asset', {}).get('iamPolicy', {}).get('policyBlob', {}).get('bindings', [])]
            data = {
                'type': self.resource_type,
                'create_time': self.create_time,
                'update_time': self.update_time,
                'iam_roles': ', '.join(roles)
            }
            return self.fill_resource_owner_keys(data)

        elif self.resource_type == GOOGLE_COMPUTE_ADDRESS_VALUE:
            data = {
                'name': self.resource_name,
                'type': self.resource_type,
                'create_time': self.create_time,
                'update_time': self.update_time,
                'compute_create_time': self.resource_properties.get('creationTimestamp', ''),
                'compute_start_time': self.resource_properties.get('lastStartTimestamp', ''),
                'self_link': self.resource_properties.get('selfLink', ''),
                'start_restricted': self.resource_properties.get('startRestricted', ''),
                'purpose': self.resource_properties.get('purpose', ''),
                'description': self.resource_properties.get('description', ''),
                'address_type': self.resource_properties.get('addressType', ''),
                'network_tier': self.resource_properties.get('networkTier', ''),
                'status': self.resource_properties.get('status', ''),
                'address': self.resource_properties.get('address', ''),
            }
            return self.fill_resource_owner_keys(data)

        elif self.resource_type == GOOGLE_COMPUTE_INSTANCE_VALUE:
            data = {
                'type': self.resource_type,
                'create_time': self.create_time,
                'update_time': self.update_time,
                'related_service_accounts':
                    ', '.join([item.get('email', '') for item in self.resource_properties.get('serviceAccounts', [])])
                if self.resource_properties else '',
                'tags':  ', '.join(self.resource_properties.get('tags', {}).get('items', []))
                if self.resource_properties else '',
                'self_link': self.resource_properties.get('selfLink', ''),
                'status': self.resource_properties.get('status', ''),
                'ip_addresses':
                    ', '.join([item.get('networkIP', '') for item in self.resource_properties.get('networkInterfaces', [])])
                    if self.resource_properties else '',
            }
            return self.fill_resource_owner_keys(data)
        else:
            return dict_to_flat(self.resource_properties)

    def fill_resource_owner_keys(self, data):
        for key, values in self.resource_owners.items():
            if values:
                data.update({
                    f"resourceOwners_{key}": ', '.join(values)
                })

        return data

    def to_enrichment_data(self, prefix=None):
        data = self.to_table()
        return add_prefix_to_dict(dict_to_flat(data), prefix) if prefix else data
