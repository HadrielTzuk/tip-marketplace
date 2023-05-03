from TIPCommon import dict_to_flat, add_prefix_to_dict
from SiemplifyUtils import convert_string_to_unix_time
import uuid
import copy

ENRICHMENT_PREFIX = u"FireEyeHX"

AlertSourceTypes = {
    u'any': None,
    u'exd (exploit detection)': u'exd',
    u'mal (malware alert)': u'mal',
    u'ioc (indicator of compromise)': u'ioc'
}


class Indicator(object):
    def __init__(self, raw_data, _id=None, uri_name=None, name=None, display_name=None, description=None, category=None,
                 created_by=None, create_actor=None, update_actor=None, create_text=None,
                 signature=None, active_since=None, platforms=None, stats=None, **kwargs):
        self.raw_data = raw_data
        self._id = _id
        self.uri_name = uri_name
        self.name = name
        self.display_name = display_name
        self.description = description
        self.category = category
        self.created_by = created_by
        self.create_actor = create_actor
        self.update_actor = update_actor
        self.create_text = create_text
        self.signature = signature
        self.active_since = active_since
        self.platforms = platforms
        self.stats = stats

    def as_csv(self):
        return {
            u"ID": self._id,
            u"Name": self.name,
            u"URI Name": self.uri_name,
            u"Display Name": self.display_name,
            u"Description": self.description,
            u"Category": self.category.get(u"name") if self.category else None,
            u"Category URI Name": self.category.get(u"uri_name") if self.category else None,
            u"Created By": self.created_by,
            u"OS": u", ".join(self.platforms) if self.platforms else None,
            u"Signature": self.signature,
            u"Active Since": self.active_since,
            u"Active Conditions": self.stats.get(u"active_conditions") if self.stats else None,
            u"Hosts with Alerts": self.stats.get(u"alerted_agents") if self.stats else None,
            u"Source Alerts": self.stats.get(u"source_alerts") if self.stats else None
        }


class Host(object):
    def __init__(self, raw_data, _id=None, agent_version=None, excluded_from_containment=None,
                 containment_missing_software=None, containment_queued=None, containment_state=None,
                 stats=None, hostname=None, domain=None, gmt_offset_seconds=None, timezone=None,
                 primary_ip_address=None, last_audit_timestamp=None, last_poll_timestamp=None, last_poll_ip=None,
                 last_alert=None, last_alert_timestamp=None, os=None, primary_mac=None, **kwargs):
        self.raw_data = raw_data
        self._id = _id
        self.agent_version = agent_version
        self.excluded_from_containment = excluded_from_containment
        self.containment_missing_software = containment_missing_software
        self.containment_queued = containment_queued
        self.containment_state = containment_state
        self.hostname = hostname
        self.domain = domain
        self.gmt_offset_seconds = gmt_offset_seconds
        self.timezone = timezone
        self.primary_ip_address = primary_ip_address
        self.last_audit_timestamp = last_audit_timestamp
        self.last_poll_timestamp = last_poll_timestamp
        self.last_poll_ip = last_poll_ip
        self.last_alert = last_alert
        self.last_alert_timestamp = last_alert_timestamp
        self.os = os
        self.primary_mac = primary_mac
        self.stats = stats

    def as_enrichment_data(self):
        return add_prefix_to_dict(dict_to_flat(self.raw_data), ENRICHMENT_PREFIX)

    def as_csv(self):
        return {
            u"ID": self._id,
            u"Hostname": self.hostname,
            u"Domain": self.domain,
            u"Agent Version": self.agent_version,
            u"Timezone": self.timezone,
            u"OS": self.os.get(u"product_name") if self.os else None,
            u"Agent Last Poll": self.last_poll_timestamp,
            u"MAC Address": self.primary_mac,
            u"IP Address": self.primary_ip_address,
            u"Containment State": self.containment_state,
            u"Malware Alerts Count": self.stats.get(u"malware_alerts") if self.stats else None,
            u"Generic Alerts Count": self.stats.get(u"generic_alerts") if self.stats else None,
            u"Exploit Alerts Count": self.stats.get(u"exploit_alerts") if self.stats else None,
            u"Exploit Blocks Count": self.stats.get(u"exploit_blocks") if self.stats else None,
            u"Total Alerts Count": self.stats.get(u"alerts") if self.stats else None,
            u"Last Alert Timestamp": self.last_alert_timestamp
        }

    @property
    def malware_alerts(self):
        return self.stats.get(u"malware_alerts") if self.stats else 0


class Alert(object):
    def __init__(self, raw_data, _id=None, agent=None, condition=None, indicator=None, event_at=None,
                 matched_at=None, reported_at=None, source=None, subtype=None, matched_source_alerts=None,
                 resolution=None, is_false_positive=None, event_id=None, event_type=None, event_values=None,
                 md5values=None, group_id=None, **kwargs):
        self.raw_data = raw_data
        self.raw_data['event_type'] = source
        self.agent = agent
        self._id = _id
        self.group_id = group_id
        self.condition = condition
        self.indicator = indicator
        self.event_at = event_at
        self.matched_at = matched_at
        self.reported_at = reported_at
        self.source = source
        self.subtype = subtype
        self.matched_source_alerts = matched_source_alerts
        self.resolution = resolution
        self.is_false_positive = is_false_positive
        self.event_id = event_id
        self.event_type = event_type
        self.event_values = event_values
        self.md5values = md5values
        self.type = u'{0} {1}'.format(self.source, self.subtype) if self.subtype else self.source
        self.host_id = self.agent.get(u"_id") if self.agent else None
        try:
            self.timestamp = convert_string_to_unix_time(self.reported_at)
        except Exception:
            self.timestamp = 1

        try:
            self.event_at_ms = convert_string_to_unix_time(event_at)
        except Exception:
            self.event_at_ms = 1

        try:
            self.matched_at_ms = convert_string_to_unix_time(matched_at)
        except Exception:
            self.matched_at_ms = 1

        try:
            self.reported_at_ms = convert_string_to_unix_time(reported_at)
        except Exception:
            self.reported_at_ms = 1

    def attach_host_info(self, host_info):
        self.raw_data['agent'] = host_info

    def as_json(self):
        return self.raw_data

    def as_csv(self):
        return {
            u"Alert ID": self._id,
            u"Agent ID": self.agent.get(u"_id") if self.agent else None,
            u"Condition ID": self.condition.get(u"_id") if self.condition else None,
            u"Indicator Name": self.indicator.get(u"name") if self.indicator else None,
            u"Indicator URI Name": self.indicator.get(u"uri_name") if self.indicator else None,
            u"Indicator Signature": self.indicator.get(u"signature") if self.indicator else None,
            u"Indicator Category": self.indicator.get(u"category") if self.indicator else None,
            u"Hashes": u", ".join(self.md5values) if self.md5values else None,
            u"Event ID": self.event_id,
            u"Event Type": self.event_type,
            u"Event At": self.event_at,
            u"Matched At": self.matched_at,
            u"Reported At": self.reported_at,
            u"Is False Positive": self.is_false_positive,
            u"Resolution": self.resolution,
            u"Alert Type": self.source
        }

    def get_alert_info(self, alert_info, environment_common):
        alert_info.environment = environment_common.get_environment(self.raw_data)
        alert_info.ticket_id = u'{}_{}'.format(self._id, unicode(uuid.uuid4()))
        alert_info.display_id = alert_info.ticket_id
        alert_info.name = u'FireEye HX Alert: {}'.format(self.type)
        alert_info.description = "FireEye HX Alert {0} ".format(self._id)
        alert_info.device_vendor = u'FireEye'
        alert_info.device_product = u'FireEye HX'
        alert_info.priority = 60
        alert_info.rule_generator = alert_info.name
        alert_info.start_time = convert_string_to_unix_time(self.event_at)
        alert_info.end_time = alert_info.start_time
        alert_info.events = [dict_to_flat(self.raw_data)]
        alert_info.source_grouping_identifier = self.group_id
        alert_info.extensions = {
            u"alert_group": self.group_id
        }

        return alert_info


class FileAcquisition(object):
    def __init__(self, raw_data, _id=None, _revision=None, error_message=None, comment=None, state=None,
                 md5=None, request_time=None, request_actor=None, req_path=None, req_filename=None,
                 req_use_api=None, zip_passphrase=None, finish_time=None, indicator=None, host=None,
                 alert=None, condition=None, **kwargs):
        self.raw_data = raw_data
        self.error_message = error_message
        self._id = _id
        self._revision = _revision
        self.comment = comment
        self.indicator = indicator
        self.state = state
        self.md5 = md5
        self.request_time = request_time
        self.request_actor = request_actor
        self.req_path = req_path
        self.req_filename = req_filename
        self.req_use_api = req_use_api
        self.zip_passphrase = zip_passphrase
        self.finish_time = finish_time
        self.host = host
        self.alert = alert
        self.condition = condition

    def as_csv(self):
        return {
            u"Acquisition ID": self._id,
            u"Agent ID": self.host.get(u"_id") if self.host else None,
            u"Condition ID": self.condition.get(u"_id") if self.condition else None,
            u"Alert ID": self.alert.get(u"_id") if self.alert else None,
            u"Comment": self.comment,
            u"Error Message": self.error_message,
            u"State": self.state,
            u"MD5": self.md5,
            u"Request Time": self.request_time,
            u"Finish Time": self.finish_time,
            u"Requested By": self.request_actor.get(u"username") if self.request_actor else None,
            u"File Name": self.req_filename,
            u"File Path": self.req_path,
            u"Acquired Using": u"API" if self.req_use_api else u"API",
            u"Zip Passphrase": self.zip_passphrase
        }

class GroupAlerts(object):
    def __init__(self, raw_data, id=None, indicator_display_name=None, event_at=None, matched_at=None, reported_at=None, source=None, event_type=None):
        self.raw_data = raw_data
        self.id = id
        self.indicator_display_name = indicator_display_name
        self.event_at = event_at
        self.matched_at = matched_at
        self.reported_at = reported_at
        self.source = source
        self.event_type = event_type
        
        
    def to_table(self):
        return{
            u"Alert FireEye HX ID": self.id,
            u"Indicator Name": self.indicator_display_name,
            u"Event Time": self.event_at,
            u"Matched Time": self.matched_at,
            u"Reported Time": self.reported_at,            
            u"Source": self.source,    
            u"Event Type": self.event_type  
        }

    def to_json(self, group_id):
        self.raw_data["group_id"] = group_id
        return self.raw_data


class Ack(object):
    def __init__(self, raw_data, total=None, entiries_ids=None):
        self.raw_data = raw_data
        self.total = total
        self.entiries_ids = entiries_ids


class Group(object):
    def __init__(self, raw_data, assessment=None, alert_group_id=None, first_event=None, last_event=None, ack=None,
                 last_event_id=None, events_count=None, detected_by=None):
        self.raw_data = raw_data
        self.assessment = assessment
        self.alert_group_id = alert_group_id
        self.first_event = first_event
        self.last_event = last_event
        self.ack = ack
        self.last_event_id = last_event_id
        self.events_count = events_count
        self.detected_by = detected_by
        
    def to_table(self):
        return{
            u"Assessment": self.assessment,
            u"Alert Group ID": self.alert_group_id,
            u"First Event": self.first_event,
            u"Last Event": self.last_event,
            u"Acknowledged": self.ack,            
            u"Last Alert HX ID": self.last_event_id
        }
        
    def as_csv(self):
        return{
            u"Assessment": self.assessment,
            u"Alert Group ID": self.alert_group_id,
            u"First Event At": self.first_event,
            u"Last Event At": self.last_event,
            u"Acknowledged": self.ack,
            u"Events Count": self.events_count,
            u"Detected By": self.detected_by
        }

    def to_json(self):
        return self.raw_data
