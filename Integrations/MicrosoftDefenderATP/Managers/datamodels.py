from abc import abstractmethod, ABCMeta
from enum import Enum
from SiemplifyUtils import dict_to_flat, convert_string_to_unix_time
from constants import DEFAULT_VENDOR_NAME, DEFAULT_PRODUCT_NAME
import uuid
import json


class AbstractData(object):
    """
    Abstract Data Model for others Data Models
    """
    __metaclass__ = ABCMeta

    def to_table(self):
        return [self.to_csv()]

    def to_csv(self):
        return dict_to_flat(self.to_json())

    @abstractmethod
    def to_json(self):
        pass

    @abstractmethod
    def to_enrichment_data(self):
        pass

    @staticmethod
    def convert_list_to_comma_string(values_list):
        if not values_list:
            return ''
        return ', '.join(values_list) if isinstance(values_list, list) else values_list


class DefenderPriorityEnum(Enum):
    UNSPECIFIED = u"UnSpecified"
    INFO = u"Informational"
    LOW = u"Low"
    MEDIUM = u"Medium"
    HIGH = u"High"


class SiemplifyPriorityEnum(Enum):
    UNSPECIFIED = -1
    INFO = -1
    LOW = 40
    MEDIUM = 60
    HIGH = 80


class AlertUser(AbstractData):
    def __init__(self, accountName=None, domainName=None, **kwargs):
        self.account_name = accountName
        self.domain_name = domainName

    def to_json(self):
        return {
            u'account_name': self.account_name,
            u'domain_name': self.domain_name
        }

    def to_enrichment_data(self):
        pass


class Indicator(AbstractData):
    def __init__(self, raw_data=None, identifier=None, indicator_value=None, indicator_type=None, action=None, severity=None,
                 description=None, title=None, recommended_actions=None):
        self.raw_data = raw_data
        self.identifier = identifier
        self.indicator_value = indicator_value
        self.indicator_type = indicator_type
        self.action = action
        self.severity = severity
        self.description = description
        self.title = title
        self.recommended_actions = recommended_actions

    def to_json(self):
        return self.raw_data

    def to_enrichment_data(self):
        pass

    def to_table(self):
        data = dict_to_flat({
            "Type": self.indicator_type,
            "Action": self.action,
            "Severity": self.severity,
            "Description": self.description,
            "Title": self.title,
            "Recommendation": self.recommended_actions
        })
        data = {key: value for key, value in data.items() if value is not None}
        return data


class AlertFile(AbstractData):
    def __init__(self, sha1=None, sha256=None, filePath=None, fileName=None, **kwargs):
        self.sha1 = sha1
        self.sha256 = sha256
        self.file_path = filePath
        self.file_name = fileName

    def to_json(self):
        return {
            u'sha1': self.sha1,
            u'sha256': self.sha256,
            u'file_path': self.file_path,
            u'file_name': self.file_name,
        }

    def to_enrichment_data(self):
        pass


class Alert(AbstractData):
    def __init__(
            self,
            raw_data,
            id=None,
            incidentId=None,
            investigationId=None,
            assignedTo=None,
            severity=None,
            status=None,
            classification=None,
            determination=None,
            investigationState=None,
            detectionSource=None,
            category=None,
            threatFamilyName=None,
            title=None,
            description=None,
            alertCreationTime=None,
            firstEventTime=None,
            lastEventTime=None,
            lastUpdateTime=None,
            resolvedTime=None,
            machineId=None,
            alertUser=None,
            comments=None,
            alertFiles=None,
            alertDomains=None,
            alertIps=None,
            alertProcesses=None,
            **kwargs
    ):
        self.raw_data = raw_data
        self.id = id
        self.incident_id = incidentId
        self.investigation_id = investigationId
        self.assigned_to = assignedTo
        self.severity = severity
        self.status = status
        self.classification = classification
        self.determination = determination
        self.investigation_state = investigationState
        self.detection_source = detectionSource
        self.category = category
        self.threat_family_name = threatFamilyName
        self.title = title
        self.description = description
        self.alert_creation_time = alertCreationTime
        self.alert_creation_time_timestamp = convert_string_to_unix_time(alertCreationTime)
        self.first_event_time = firstEventTime
        self.last_event_time = lastEventTime
        self.last_update_time = lastUpdateTime
        self.resolved_time = resolvedTime
        self.machine_id = machineId
        self.alert_user = AlertUser(**alertUser) if alertUser else None
        self.comments = comments
        self.alert_files = [AlertFile(**alert_file) for alert_file in alertFiles] if alertFiles else []
        self.alert_domains = alertDomains
        self.alert_ips = alertIps
        self.alert_processes = alertProcesses
        self.alert_data = {}

    def to_json(self):
        return {
            u'id': self.id,
            u'incident_id': self.incident_id,
            u'investigation_id': self.investigation_id,
            u'assigned_to': self.assigned_to,
            u'severity': self.severity,
            u'status': self.status,
            u'classification': self.classification,
            u'determination': self.determination,
            u'investigation_state': self.investigation_state,
            u'detection_source': self.detection_source,
            u'category': self.category,
            u'threat_family_name': self.threat_family_name,
            u'title': self.title,
            u'description': self.description,
            u'alert_creation_time': self.alert_creation_time,
            u'first_event_time': self.first_event_time,
            u'last_event_time': self.last_event_time,
            u'last_update_time': self.last_update_time,
            u'resolved_time': self.resolved_time,
            u'machine_id': self.machine_id,
            u'alert_user': self.alert_user.to_json() if self.alert_user else None,
            u'alert_files': [file.to_json() for file in self.alert_files],
            u'comments': self.comments,
            u'alert_domains': self.alert_domains,
            u'alert_ips': self.alert_ips,
            u'alert_processes': self.alert_processes,
        }

    def to_enrichment_data(self):
        pass

    def to_table(self):
        return {
            u'Alert ID': self.id,
            u'Incident ID': self.incident_id,
            u'Status': self.status,
            u'Severity': self.severity,
            u'Title': self.title,
            u'Description': self.description,
            u'Assigned To': self.assigned_to,
            u'Category': self.category,
            u'Alert Creation Time': self.alert_creation_time,
            u'Last Update Time': self.last_update_time
        }

    def to_extension(self, extended=False):
        extensions = {
            u'incidentId': self.incident_id,
            u'investigationId': self.investigation_id,
            u'assignedTo': self.assigned_to,
            u'status': self.status,
            u'classification': self.classification,
            u'determination': self.determination,
            u'investigationState': self.investigation_state,
            u'detectionSource': self.detection_source,
            u'category': self.category,
            u'threatFamilyName': self.threat_family_name,
            u'machineId': self.machine_id,
            u'alertUser': self.alert_user.to_json() if self.alert_user else None,
            u'alertCreationTime': self.alert_creation_time,
            u'lastUpdateTime': self.last_update_time,
            u'resolvedTime': self.resolved_time
        }

        if extended:
            extensions[u"mitreTechniques"] = json.dumps(self.raw_data.get("mitreTechniques"))
            extensions[u"comments"] = json.dumps([dict_to_flat(comment) for comment in self.raw_data.get("comments")])

        return extensions

    def get_alert_info(self, alert_info, environment_common, device_product_field, severity):
        alert_info.environment = environment_common.get_environment(self.raw_data)
        alert_info.display_id = str(uuid.uuid4())
        alert_info.ticket_id = self.id
        alert_info.name = self.title
        alert_info.description = self.description
        alert_info.device_vendor = DEFAULT_VENDOR_NAME
        alert_info.device_product = self.raw_data.get(device_product_field) or DEFAULT_PRODUCT_NAME
        alert_info.rule_generator = self.detection_source
        alert_info.source_grouping_identifier = self.incident_id
        alert_info.extensions = self.to_extension(extended=True)
        alert_info.priority = severity
        alert_info.start_time = convert_string_to_unix_time(self.first_event_time)
        alert_info.end_time = convert_string_to_unix_time(self.last_event_time)
        alert_info.events = self.to_events()

        return alert_info

    def set_events(self, alert_data):
        self.alert_data = alert_data

    def to_events(self):
        events = []
        events.extend([dict_to_flat(self.prepare_device_event(device)) for device in self.alert_data.get("devices", [])])
        events.extend([dict_to_flat(self.prepare_entity_event(entity)) for entity in self.alert_data.get("entities", [])])
        return events

    def prepare_event_additional_fields(self):
        return {
            "alertCreationTime": self.alert_creation_time,
            "firstEventTime": self.first_event_time,
            "lastEventTime": self.last_event_time,
            "lastUpdateTime": self.last_update_time
        }

    def prepare_device_event(self, device):
        device["EventName"] = "device"
        device["ProductName"] = DEFAULT_PRODUCT_NAME
        device.update(self.prepare_event_additional_fields())
        return device

    def prepare_entity_event(self, entity):
        entity["EventName"] = entity.get("entityType")
        entity["ProductName"] = DEFAULT_PRODUCT_NAME
        entity.update(self.prepare_event_additional_fields())
        return entity


class Machine(AbstractData):
    def __init__(
            self,
            raw_data,
            id=None,
            computerDnsName=None,
            firstSeen=None,
            lastSeen=None,
            osPlatform=None,
            osVersion=None,
            osProcessor=None,
            version=None,
            lastIpAddress=None,
            lastExternalIpAddress=None,
            agentVersion=None,
            osBuild=None,
            healthStatus=None,
            rbacGroupId=None,
            rbacGroupName=None,
            riskScore=None,
            exposureLevel=None,
            aadDeviceId=None,
            machineTags=None,
            **kwargs
    ):
        self.raw_data = raw_data
        self.id = id
        self.computer_dns_name = computerDnsName
        self.first_seen = firstSeen
        self.last_seen = lastSeen
        self.last_seen_unix = convert_string_to_unix_time(lastSeen) if lastSeen else 0
        self.os_platform = osPlatform
        self.os_version = osVersion
        self.os_processor = osProcessor
        self.version = version
        self.last_ip_address = lastIpAddress
        self.last_external_ip_address = lastExternalIpAddress
        self.agent_version = agentVersion
        self.os_build = osBuild
        self.health_status = healthStatus
        self.rbac_group_id = rbacGroupId
        self.rbac_group_name = rbacGroupName
        self.risk_score = riskScore
        self.exposure_level = exposureLevel
        self.aad_device_id = aadDeviceId
        self.machine_tags = machineTags

    def to_json(self):
        return {
            u'id': self.id,
            u'computer_dns_name': self.computer_dns_name,
            u'first_seen': self.first_seen,
            u'last_seen': self.last_seen,
            u'os_platform': self.os_platform,
            u'os_version': self.os_version,
            u'os_processor': self.os_processor,
            u'version': self.version,
            u'last_ip_address': self.last_ip_address,
            u'last_external_ip_address': self.last_external_ip_address,
            u'agent_version': self.agent_version,
            u'os_build': self.os_build,
            u'health_status': self.health_status,
            u'rbac_group_id': self.rbac_group_id,
            u'rbac_group_name': self.rbac_group_name,
            u'risk_score': self.risk_score,
            u'exposure_level': self.exposure_level,
            u'aad_device_id': self.aad_device_id,
            u'machine_tags': self.machine_tags,
        }

    def to_enrichment_data(self):
        enrichment_data = {
            u'machine_id': self.id,
            u'computer_dns_name': self.computer_dns_name,
            u'agent_version': self.agent_version,
            u'health_status': self.health_status,
            u'risk_score': self.risk_score,
            u'exposure_level': self.exposure_level,
            u'first_seen': self.first_seen,
            u'last_seen': self.last_seen,
            u'last_ip_address': self.last_ip_address,
            u'last_external_ip_address': self.last_external_ip_address
        }

        if self.risk_score in [u'Low', u'Medium', u'High']:
            enrichment_data[u'is_suspicious'] = self.risk_score

        if self.machine_tags:
            enrichment_data[u'machine_tags'] = self.machine_tags

        if self.os_platform:
            enrichment_data[u'os_platform'] = self.os_platform

        if self.os_version:
            enrichment_data[u'os_version'] = self.os_version

        if self.os_processor:
            enrichment_data[u'os_processor'] = self.os_processor

        if self.version:
            enrichment_data[u'version'] = self.version

        if self.os_build:
            enrichment_data[u'os_build'] = self.os_build

        if self.rbac_group_id:
            enrichment_data[u'rbac_group_id'] = self.rbac_group_id

        if self.rbac_group_name:
            enrichment_data[u'rbac_group_name'] = self.rbac_group_name

        if self.aad_device_id:
            enrichment_data[u'aad_device_id'] = self.aad_device_id

        return enrichment_data

    def to_table(self):
        return {
            u'Machine ID': self.id,
            u'Machine DNS Name': self.computer_dns_name,
            u'Risk Score': self.risk_score,
            u'Exposure Level': self.exposure_level,
            u'Health Status': self.health_status,
            u'First Seen': self.first_seen,
            u'Last Seen': self.last_seen,
            u'Last Seen Lan IP Address': self.last_ip_address,
            u'Last Seen External IP Address': self.last_external_ip_address,
            u'OS Platform': self.os_platform,
            u'OS Version': self.os_version,
            u'OS Build': self.os_build,
            u'DATP Agent Version': self.agent_version,
        }


class User(AbstractData):
    def __init__(
            self,
            raw_data,
            id=None,
            accountName=None,
            accountDomain=None,
            accountSid=None,
            firstSeen=None,
            lastSeen=None,
            mostPrevalentMachineId=None,
            leastPrevalentMachineId=None,
            logonTypes=None,
            logOnMachinesCount=None,
            isDomainAdmin=None,
            isOnlyNetworkUser=None,
            **kwargs
    ):
        self.raw_data = raw_data
        self.id = id
        self.account_name = accountName
        self.account_domain = accountDomain
        self.account_sid = accountSid
        self.first_seen = firstSeen
        self.last_seen = lastSeen
        self.most_prevalent_machine_id = mostPrevalentMachineId
        self.least_prevalent_machine_id = leastPrevalentMachineId
        self.logon_types = logonTypes
        self.log_on_machines_count = logOnMachinesCount
        self.is_domain_admin = isDomainAdmin
        self.is_only_network_user = isOnlyNetworkUser

    def to_json(self):
        return {
            u'id': self.id,
            u'account_name': self.account_name,
            u'account_domain': self.account_domain,
            u'account_sid': self.account_sid,
            u'first_seen': self.first_seen,
            u'last_seen': self.last_seen,
            u'most_prevalent_machine_id': self.most_prevalent_machine_id,
            u'least_prevalent_machine_id': self.least_prevalent_machine_id,
            u'logon_types': self.logon_types,
            u'log_on_machines_count': self.log_on_machines_count,
            u'is_domain_admin': self.is_domain_admin,
            u'is_only_network_user': self.is_only_network_user,
        }

    def to_enrichment_data(self):
        pass

    def to_table(self):
        return {
            u'ID': self.id,
            u'First Seen': self.first_seen,
            u'Last Seen': self.last_seen,
            u'Most Prevalent Machine ID': self.most_prevalent_machine_id,
            u'Least Prevalent Machine ID': self.least_prevalent_machine_id,
            u'Logon Types': self.logon_types,
            u'Log On Machines Count': self.log_on_machines_count,
            u'Is Domain Admin': self.is_domain_admin,
            u'Is Only Network User': self.is_only_network_user,
        }


class File(AbstractData):
    def __init__(
            self,
            raw_data,
            sha1=None,
            sha256=None,
            md5=None,
            globalPrevalence=None,
            globalFirstObserved=None,
            globalLastObserved=None,
            size=None,
            fileType=None,
            isPeFile=None,
            filePublisher=None,
            fileProductName=None,
            signer=None,
            issuer=None,
            signerHash=None,
            isValidCertificate=None,
            orgPrevalence=None,
            orgFirstSeen=None,
            orgLastSeen=None,
            topFileNames=None,
            **kwargs
    ):
        self.raw_data = raw_data
        self.sha1 = sha1
        self.sha256 = sha256
        self.md5 = md5
        self.global_prevalence = globalPrevalence
        self.global_first_observed = globalFirstObserved
        self.global_last_observed = globalLastObserved
        self.size = size
        self.file_type = fileType
        self.is_pe_file = isPeFile
        self.file_publisher = filePublisher
        self.file_product_name = fileProductName
        self.signer = signer
        self.issuer = issuer
        self.signer_hash = signerHash
        self.is_valid_certificate = isValidCertificate
        self.org_prevalence = orgPrevalence
        self.org_first_seen = orgFirstSeen
        self.org_last_seen = orgLastSeen
        self.top_file_names = topFileNames

    def to_json(self):
        return {
            u'sha1': self.sha1,
            u'sha256': self.sha256,
            u'md5': self.md5,
            u'global_prevalence': self.global_prevalence,
            u'global_first_observed': self.global_first_observed,
            u'global_last_observed': self.global_last_observed,
            u'size': self.size,
            u'file_type': self.file_type,
            u'is_pe_file': self.is_pe_file,
            u'file_publisher': self.file_publisher,
            u'file_product_name': self.file_product_name,
            u'signer': self.signer,
            u'issuer': self.issuer,
            u'signer_hash': self.signer_hash,
            u'is_valid_certificate': self.is_valid_certificate,
            u'org_prevalence': self.org_prevalence,
            u'org_first_seen': self.org_first_seen,
            u'org_last_seen': self.org_last_seen,
            u'top_file_names': self.top_file_names,
        }

    def to_enrichment_data(self):
        return {
            u'sha1': self.sha1,
            u'sha256': self.sha256,
            u'md5': self.md5,
            u'global_prevalence': self.global_prevalence,
            u'global_first_observed': self.global_first_observed,
            u'global_last_observed': self.global_last_observed,
            u'size': self.size,
            u'file_type': self.file_type,
            u'is_pe_file': self.is_pe_file,
            u'file_publisher': self.file_publisher,
            u'file_product_name': self.file_product_name,
            u'signer': self.signer,
            u'issuer': self.issuer,
            u'signer_hash': self.signer_hash,
            u'is_valid_certificate': self.is_valid_certificate,
            u'org_prevalence': self.org_prevalence,
            u'org_first_seen': self.org_first_seen,
            u'org_last_seen': self.org_last_seen,
            u'top_file_names': self.convert_list_to_comma_string(self.top_file_names)
        }

    def to_table(self):
        return {
            u'SHA1': self.sha1,
            u'SHA256': self.sha256,
            u'MD5': self.md5,
            u'Top File Names': self.convert_list_to_comma_string(self.top_file_names),
            u'File Type': self.file_type,
            u'Is PE file': self.is_pe_file,
            u'Organization Prevalence': self.org_prevalence,
            u'Organization First Seen': self.org_first_seen,
            u'Organization Last Seen': self.org_last_seen,
            u'Global Prevalence': self.global_prevalence,
            u'Global First Observed': self.global_first_observed,
            u'Global Last Observed': self.global_last_observed,
            u'Size': self.size,
            u'File Published': self.file_publisher,
            u'File Product Name': self.file_product_name,
            u'Is Valid Certificate': self.is_valid_certificate,
            u'Signer': self.signer,
            u'Signer Hash': self.signer_hash,
            u'Issuer': self.issuer,
        }


class Detection(AbstractData):
    def __init__(
            self,
            raw_data,
            Actor=None,
            AlertId=None,
            AlertPart=None,
            AlertTime=None,
            AlertTitle=None,
            Category=None,
            CloudCreatedMachineTags=None,
            CommandLine=None,
            ComputerDnsName=None,
            CreatorIocName=None,
            CreatorIocValue=None,
            Description=None,
            DeviceCreatedMachineTags=None,
            DeviceID=None,
            ExternalId=None,
            FileHash=None,
            FileName=None,
            FilePath=None,
            FullId=None,
            IncidentLinkToWDATP=None,
            InternalIPv4List=None,
            InternalIPv6List=None,
            IoaDefinitionId=None,
            IocName=None,
            IocUniqueId=None,
            IocValue=None,
            IpAddress=None,
            LastProcessedTimeUtc=None,
            LinkToWDATP=None,
            LogOnUsers=None,
            MachineDomain=None,
            MachineGroup=None,
            MachineName=None,
            Md5=None,
            RemediationAction=None,
            RemediationIsSuccess=None,
            ReportID=None,
            Severity=None,
            Sha1=None,
            Sha256=None,
            Source=None,
            ThreatCategory=None,
            ThreatFamily=None,
            ThreatName=None,
            Url=None,
            UserDomain=None,
            UserName=None,
            WasExecutingWhileDetected=None,
            **kwargs
    ):
        self.raw_data = raw_data
        self.actor = Actor
        self.alert_id = AlertId
        self.alert_part = AlertPart
        self.alert_time = AlertTime
        self.alert_title = AlertTitle
        self.category = Category
        self.cloud_created_machine_tags = CloudCreatedMachineTags
        self.command_line = CommandLine
        self.computer_dns_name = ComputerDnsName
        self.creator_ioc_name = CreatorIocName
        self.creator_ioc_value = CreatorIocValue
        self.description = Description
        self.device_created_machine_tags = DeviceCreatedMachineTags
        self.device_id = DeviceID
        self.external_id = ExternalId
        self.file_hash = FileHash
        self.file_name = FileName
        self.file_path = FilePath
        self.full_id = FullId
        self.incident_link_to_wdatp = IncidentLinkToWDATP
        self.internal_ipv4_list = InternalIPv4List
        self.internal_ipv6_list = InternalIPv6List
        self.ioa_definition_id = IoaDefinitionId
        self.ioc_name = IocName
        self.ioc_unique_id = IocUniqueId
        self.ioc_value = IocValue
        self.ip_address = IpAddress
        self.last_processed_time_utc = LastProcessedTimeUtc
        self.link_to_wdatp = LinkToWDATP
        self.log_on_users = LogOnUsers
        self.machine_domain = MachineDomain
        self.machine_group = MachineGroup
        self.machine_name = MachineName
        self.md5 = Md5
        self.remediation_action = RemediationAction
        self.remediation_is_success = RemediationIsSuccess
        self.report_id = ReportID
        self.severity = Severity
        self.sha1 = Sha1
        self.sha256 = Sha256
        self.source = Source
        self.threat_category = ThreatCategory
        self.threat_family = ThreatFamily
        self.threat_name = ThreatName
        self.url = Url
        self.user_domain = UserDomain
        self.user_name = UserName
        self.was_executing_while_detected = WasExecutingWhileDetected

    def to_json(self):
        return {
            u'actor': self.actor,
            u'alert_id': self.alert_id,
            u'alert_part': self.alert_part,
            u'alert_time': self.alert_time,
            u'alert_title': self.alert_title,
            u'category': self.category,
            u'cloud_created_machine_tags': self.cloud_created_machine_tags,
            u'command_line': self.command_line,
            u'computer_dns_name': self.computer_dns_name,
            u'creator_ioc_name': self.creator_ioc_name,
            u'creator_ioc_value': self.creator_ioc_value,
            u'description': self.description,
            u'device_created_machine_tags': self.device_created_machine_tags,
            u'device_id': self.device_id,
            u'external_id': self.external_id,
            u'file_hash': self.file_hash,
            u'file_name': self.file_name,
            u'file_path': self.file_path,
            u'full_id': self.full_id,
            u'incident_link_to_wdatp': self.incident_link_to_wdatp,
            u'internal_ipv4_list': self.internal_ipv4_list,
            u'internal_ipv6_list': self.internal_ipv6_list,
            u'ioa_definition_id': self.ioa_definition_id,
            u'ioc_name': self.ioc_name,
            u'ioc_unique_id': self.ioc_unique_id,
            u'ioc_value': self.ioc_value,
            u'ip_address': self.ip_address,
            u'last_processed_time_utc': self.last_processed_time_utc,
            u'link_to_wdatp': self.link_to_wdatp,
            u'log_on_users': self.log_on_users,
            u'machine_domain': self.machine_domain,
            u'machine_group': self.machine_group,
            u'machine_name': self.machine_name,
            u'md5': self.md5,
            u'remediation_action': self.remediation_action,
            u'remediation_is_success': self.remediation_is_success,
            u'report_id': self.report_id,
            u'severity': self.severity,
            u'sha1': self.sha1,
            u'sha256': self.sha256,
            u'source': self.source,
            u'threat_category': self.threat_category,
            u'threat_family': self.threat_family,
            u'threat_name': self.threat_name,
            u'url': self.url,
            u'user_domain': self.user_domain,
            u'user_name': self.user_name,
            u'was_executing_while_detected': self.was_executing_while_detected,
        }

    def to_enrichment_data(self):
        pass


class QueryResult(AbstractData):
    def __init__(self, raw_data, **kwargs):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data.get('Results')

    def to_enrichment_data(self):
        pass

    def to_csv(self):
        return self.to_json()

    def to_table(self):
        return self.to_csv()


class RelatedFileInfo(AbstractData):
    def __init__(self, fileIdentifier, fileIdentifierType, **kwargs):
        self.file_identifier = fileIdentifier
        self.file_identifier_type = fileIdentifierType

    def to_json(self):
        return {
            u'file_identifier': self.file_identifier,
            u'file_identifier_type': self.file_identifier_type
        }

    def to_enrichment_data(self):
        pass


class MachineTask(AbstractData):
    def __init__(
            self,
            raw_data,
            id=None,
            type=None,
            requestor=None,
            requestorComment=None,
            status=None,
            machineId=None,
            creationDateTimeUtc=None,
            lastUpdateDateTimeUtc=None,
            cancellationRequestor=None,
            cancellationComment=None,
            cancellationDateTimeUtc=None,
            errorHResult=None,
            scope=None,
            relatedFileInfo=None,
            **kwargs
    ):
        self.raw_data = raw_data
        self.id = id
        self.type = type
        self.requestor = requestor
        self.requestor_comment = requestorComment
        self.status = status
        self.machine_id = machineId
        self.creation_date_time_utc = creationDateTimeUtc
        self.last_update_date_time_utc = lastUpdateDateTimeUtc
        self.cancellation_requestor = cancellationRequestor
        self.cancellation_comment = cancellationComment
        self.cancellation_date_time_utc = cancellationDateTimeUtc
        self.error_h_result = errorHResult
        self.scope = scope
        self.related_file_info = RelatedFileInfo(**relatedFileInfo) if relatedFileInfo else relatedFileInfo

    @property
    def is_succeeded(self):
        return self.status == u'Succeeded'

    @property
    def is_pending(self):
        return self.status == u'Pending'

    @property
    def is_in_progress(self):
        return self.status == u'InProgress'

    @property
    def is_timeout(self):
        return self.status == u'TimeOut'

    @property
    def is_failed(self):
        return self.status == u'Failed'

    @property
    def is_cancelled(self):
        return self.status == u'Cancelled'

    @property
    def is_finished_and_not_succeeded(self):
        return any([
            self.is_failed,
            self.is_timeout,
            self.is_cancelled,
        ])

    def to_json(self):
        return {
            u'id': self.id,
            u'type': self.type,
            u'requestor': self.requestor,
            u'requestor_comment': self.requestor_comment,
            u'status': self.status,
            u'machine_id': self.machine_id,
            u'creation_date_time_utc': self.creation_date_time_utc,
            u'last_update_date_time_utc': self.last_update_date_time_utc,
            u'cancellation_requestor': self.cancellation_requestor,
            u'cancellation_comment': self.cancellation_comment,
            u'cancellation_date_time_utc': self.cancellation_date_time_utc,
            u'error_h_result': self.error_h_result,
            u'scope': self.scope,
            u'related_file_info': self.related_file_info.to_json() if self.related_file_info else self.related_file_info,
        }

    def to_table(self):
        return {
            u'Task ID': self.id,
            u'Status': self.status
        }

    def to_enrichment_data(self):
        pass

    def __eq__(self, other):
        return self.id == other.id

    def __hash__(self):
        return hash((self.id, ))
