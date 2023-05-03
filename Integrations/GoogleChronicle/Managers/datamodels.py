from TIPCommon import dict_to_flat, add_prefix_to_dict
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import convert_string_to_unix_time
from urllib.parse import urlparse
import hashlib
import json
import uuid
from copy import deepcopy
import consts
import utils
from utils import generate_hash, separate_data_per_multiple_values_keys, rename_dict_key, fix_key_value_pair, \
    get_prefix_from_string


class IOC(object):
    class Source(object):
        def __init__(self, raw_data, category=None, intRawConfidenceScore=None, normalizedConfidenceScore=None,
                     rawSeverity=None, source=None, **kwargs):
            self.raw_data = raw_data
            self.category = category
            self.int_raw_confidence_score = intRawConfidenceScore
            self.normalized_confidence_score = str(normalizedConfidenceScore).lower() if normalizedConfidenceScore else None
            self.raw_severity = str(rawSeverity).lower() if rawSeverity else None
            self.source = source

    def __init__(self, raw_data, domain_name=None, firstSeenTime=None, iocIngestTime=None, lastSeenTime=None,
                 sources=None, uri=None, fallback_severity=None, **kwargs):
        self.raw_data = raw_data
        self.flat_raw_data = dict_to_flat(self.raw_data)
        self.domain_name = domain_name
        self.first_seen_time = firstSeenTime
        self.ioc_ingest_time = iocIngestTime
        self.last_seen_time = lastSeenTime
        self.sources = sources or []
        self.uri = uri
        self.id = generate_hash(f"{self.domain_name}{self.last_seen_time}")
        self.fallback_severity = fallback_severity
        self.highest_siemplify_severity = self.get_highest_siemplify_severity \
                                          or consts.SIEMPLIFY_SEVERITIES.get(self.fallback_severity.lower()) if self.fallback_severity else None

        try:
            self.first_seen_time_ms = convert_string_to_unix_time(self.first_seen_time)
        except Exception:
            self.first_seen_time_ms = 1

        try:
            self.ioc_ingest_time_ms = convert_string_to_unix_time(self.ioc_ingest_time)
        except Exception:
            self.ioc_ingest_time_ms = 1

        try:
            self.last_seen_time_ms = convert_string_to_unix_time(self.last_seen_time)
        except Exception:
            self.last_seen_time_ms = 1

    def as_json(self):
        return self.raw_data

    def as_csv(self):
        return {
            "Domain": self.domain_name,
            "Category": self.sources[0].category if self.sources else "",
            "Source": self.sources[0].source if self.sources else "",
            "Confidence": self.sources[0].normalized_confidence_score if self.sources else "",
            "Severity": self.sources[0].raw_severity if self.sources else "",
            "IoC Ingest Time": self.ioc_ingest_time,
            "IoC First Seen Time": self.first_seen_time,
            "IoC Last Seen Time": self.last_seen_time,
            "URI": self.uri[0] if self.uri else ""
        }

    @property
    def hash_id(self):
        temp_data = deepcopy(self.raw_data)
        temp_data.pop("uri", None)
        return hashlib.md5(json.dumps(temp_data, sort_keys=True).encode("utf8")).hexdigest()

    @property
    def siemplify_severity(self):
        return consts.SIEMPLIFY_SEVERITIES.get(str(self.sources[0].raw_severity).lower() if self.sources else "info", -1)

    @property
    def unified_siemplify_severity(self):
        severity_value = (
            next((source.raw_severity for source in self.sources
                  if source.raw_severity and source.raw_severity != consts.NOT_ASSIGNED), None)
        )

        return consts.SIEMPLIFY_SEVERITIES.get(severity_value.lower()) if severity_value else None

    @property
    def get_highest_siemplify_severity(self):
        return max([consts.SIEMPLIFY_SEVERITIES.get(source.raw_severity) for source in self.sources
                    if source.raw_severity and source.raw_severity != consts.NOT_ASSIGNED], default=None)

    @property
    def average_confidence_score(self):
        confidence_scores = [int(source.int_raw_confidence_score) for source in self.sources
                             if source.int_raw_confidence_score]

        return sum(confidence_scores) / len(confidence_scores) if confidence_scores else None

    @property
    def average_normalized_confidence_score(self):
        normalized_confidence_scores = [consts.SIEMPLIFY_SEVERITIES.get(source.normalized_confidence_score)
                                        for source in self.sources
                                        if source.normalized_confidence_score is not None
                                        and source.normalized_confidence_score != consts.NOT_ASSIGNED]

        return sum(normalized_confidence_scores) / len(normalized_confidence_scores) if normalized_confidence_scores else None

    def as_alert_info(self, environment_common):
        """
        Create an AlertInfo out of the current finding
        :param environment_common: {EnvironmentHandle} The environment common object for fetching the environment
        :return: {AlertInfo} The created AlertInfo object
        """
        alert_info = AlertInfo()
        alert_info.environment = environment_common.get_environment(dict_to_flat(self.raw_data))
        alert_info.ticket_id = str(uuid.uuid4())
        alert_info.display_id = str(uuid.uuid4())
        alert_info.name = f"IOC Domain Match: {self.domain_name}"
        alert_info.description = f"IOC Domain Match: : {self.domain_name}"
        alert_info.device_vendor = consts.VENDOR
        alert_info.device_product = self.sources[0].source if self.sources else consts.PRODUCT
        alert_info.priority = self.siemplify_severity
        alert_info.rule_generator = "IOC Domain Match"
        alert_info.start_time = self.first_seen_time_ms
        alert_info.end_time = self.last_seen_time_ms
        alert_info.events = self.events

        return alert_info

    def as_unified_alert_info(self, alert_info, environment_common, device_product_field):
        """
        Prepare AlertInfo for unified connector
        :param alert_info: {AlertInfo} AlertInfo object
        :param environment_common: {EnvironmentHandle} environment common object for fetching the environment
        :param device_product_field: {str} key to use for device product extraction
        :return: {AlertInfo} created AlertInfo object
        """
        alert_info.environment = environment_common.get_environment(self.flat_raw_data)
        alert_info.ticket_id = self.id
        alert_info.display_id = str(uuid.uuid4())
        alert_info.name = "IOC Match"
        alert_info.description = self.get_description()
        alert_info.device_vendor = consts.UNIFIED_CONNECTOR_DEVICE_VENDOR
        alert_info.priority = self.unified_siemplify_severity or consts.SIEMPLIFY_SEVERITIES.get(self.fallback_severity.lower())
        alert_info.rule_generator = "IOC Match"
        alert_info.start_time = self.last_seen_time_ms
        alert_info.end_time = self.last_seen_time_ms
        alert_info.events = self.unified_events
        alert_info.extensions = {"alert_type": consts.ALERT_TYPE_NAMES.get(consts.ALERT_TYPES.get("ioc"))}
        alert_info.device_product = next((event.get(device_product_field) for event in alert_info.events
                                          if event.get(device_product_field)), None) \
                                    or consts.UNIFIED_CONNECTOR_DEVICE_PRODUCT

        return alert_info

    @property
    def events(self):
        temp_data = deepcopy(self.raw_data)
        temp_data.pop("sources", None)

        events = []
        for source in self.sources:
            source_data = deepcopy(source.raw_data)
            source_data.update(temp_data)
            events.append(
                dict_to_flat(source_data)
            )

        return events

    @property
    def unified_events(self):
        event = deepcopy(self.flat_raw_data)
        event["alert_type"] = consts.ALERT_TYPE_NAMES.get(consts.ALERT_TYPES.get('ioc'))
        event["event_type"] = f"{consts.ALERT_TYPE_NAMES.get(consts.ALERT_TYPES.get('ioc'))}_Event"
        return [event]

    def get_description(self):
        return utils.convert_list_to_comma_string(
            [source.category or "" for source in self.sources]
        )


class IOCDetail(object):
    class Source(object):
        class Address(object):
            def __init__(self, raw_data, port=None, domain=None, ipAddress=None, **kwargs):
                self.raw_data = raw_data
                self.port = port
                self.domain = domain
                self.ip_address = ipAddress

        def __init__(self, raw_data, sourceUrl=None, category=None, strRawConfidenceScore=None, addresses=None,
                     rawSeverity=None, firstActiveTime=None, lastActiveTime=None, **kwargs):
            self.raw_data = raw_data
            self.source_url = sourceUrl
            self.category = category
            self.str_raw_confidence_score = str(strRawConfidenceScore).lower() if strRawConfidenceScore else None
            self.numeric_raw_confidence_score = consts.CONFIDENCE_TO_INT_MAPPING.get(str(strRawConfidenceScore).lower(), 0) if strRawConfidenceScore else None
            self.raw_severity = str(rawSeverity).lower() if rawSeverity else None
            self.numeric_raw_severity = consts.IOC_SEVERITIES.get(self.raw_severity, 0)
            self.addresses = addresses
            self.first_active_time = firstActiveTime
            self.last_active_time = lastActiveTime
            self.source = sourceUrl

            try:
                self.first_active_time_ms = convert_string_to_unix_time(self.first_active_time)
            except Exception:
                self.first_active_time_ms = 1

            try:
                self.last_active_time_ms = convert_string_to_unix_time(self.last_active_time)
            except Exception:
                self.last_active_time_ms = 1

        def as_enrichment(self):
            return dict_to_flat(self.raw_data)

        def to_table(self, for_domain=False):
            try:
                confidence = IOCDetail.avg_confidnce_to_ui(int(self.str_raw_confidence_score) if
                                                           self.str_raw_confidence_score else None)
            except:
                confidence = self.str_raw_confidence_score.title() if self.str_raw_confidence_score else "N/A"

            table_data = {
                "Source": self.source or "N/A",
                "Severity": self.raw_severity.title() if self.raw_severity else None,
                "Category": self.category,
                "Confidence": confidence
            }
            if not for_domain:
                table_data["Related Domains"] = utils.convert_list_to_comma_string([address.domain for address in
                                                                                    self.addresses])

            return {key: value for key, value in table_data.items() if value is not None}

    def __init__(self, raw_data, sources=None, uri=None, firstSeenTime=None, lastSeenTime=None, **kwargs):
        self.raw_data = raw_data
        self.sources = sources
        self.uri = uri
        self.first_seen = firstSeenTime
        self.last_seen = lastSeenTime
        self.first_active_time = sorted(sources, key=lambda source: (source.first_active_time is None,
                                                                     source.first_active_time))[0].first_active_time if sources else None
        self.last_active_time = sorted(sources, key=lambda source: (source.last_active_time is not None,
                                                                    source.last_active_time), reverse=True)[0].last_active_time if sources else None

    def as_enrichment(self, prefix, for_domain=False):
        if not self.sources:
            return {}

        source_addresses = []
        for source in self.sources:
            source_addresses.extend(source.addresses)

        source_categories = [source.category for source in self.sources if source.category]
        source_sources = [source.source for source in self.sources if source.source]
        address_domains = [address.domain for address in source_addresses if address.domain]

        data = {
            "severity": consts.INT_TO_SEVERITY_MAPPING.get(self.highest_source_severity[1]),
            "average_confidence": self.average_source_confidence,
            "categories": utils.convert_list_to_comma_string(source_categories),
            "sources": utils.convert_list_to_comma_string(source_sources),
            "first_seen": self.first_active_time,
            "last_seen": self.last_active_time,
            "report_link": self.uri[0] if self.uri else None
        }

        if not for_domain:
            data["related_domains"] = utils.convert_list_to_comma_string(address_domains)

        clean_enrichment_data = {k: v for k, v in data.items() if v}
        return add_prefix_to_dict(dict_to_flat(clean_enrichment_data), prefix)

    def to_table(self, for_domain=False):
        return [source.to_table(for_domain=for_domain) for source in self.sources]

    def to_insight(self, for_domain=False):
        severity_color_mapper = {
            "N/A": None,
            "Info": None,
            "Low": '#ffcc00',
            "Medium": '#ff9900',
            "High": "#ff0000"
        }

        str_highest_severity = consts.INT_TO_SEVERITY_MAPPING.get(self.highest_source_severity[1])

        insight_content = f'<h1><strong>Severity: '
        insight_content += f'<span style="color: {severity_color_mapper.get(str_highest_severity)};">' if \
            severity_color_mapper.get(str_highest_severity) else ""
        insight_content += f'{str_highest_severity or "N/A"}</span><br /></strong></h1>'
        insight_content += f'<p><strong><strong>First Active Time: {self.first_active_time or "N/A"}<br />Last Active Time: ' \
                           f'{self.last_active_time or "N/A"}</strong></strong></p><br />'

        for source in self.sources:
            insight_content += f'<h3><strong>Source: {source.source or "N/A"}<br /></strong></h3>'
            insight_content += f'<p><strong><span >Severity:<strong>'
            insight_content += f'<span style="color: {severity_color_mapper.get(source.raw_severity.title())};"> ' if \
                severity_color_mapper.get(source.raw_severity.title()) else ""
            insight_content += f'{source.raw_severity.title() or "N/A"}</span><br />'

            try:
                confidence_score = int(source.str_raw_confidence_score)
                confidence_score = IOCDetail.avg_confidnce_to_ui(confidence_score)
            except:
                confidence_score = source.str_raw_confidence_score.title() if source.str_raw_confidence_score else "N/A"

            insight_content += f'<span>Confidence: ' \
                               f'{confidence_score}<br />' \
                               f'Category: {source.category}<br />'
            if not for_domain:
                insight_content += f'Related Domains: ' \
                                   f'{utils.convert_list_to_comma_string([address.domain for address in source.addresses]) or "N/A"}' \
                                   f'</span></strong></span></strong></p><br />'

        url = self.uri[0] if self.uri else "N/A"
        insight_content += f'<p><strong><span"><strong><span>' \
                           f'<br />Additional information is available here: <a href={url}>{url}</a></span>' \
                           f'</strong></span></strong></p><p><span>&nbsp;</span></p>'

        return insight_content

    @property
    def highest_source_severity(self):
        if not self.sources:
            return "n/a", 0

        sorted_sources = sorted(self.sources, key=lambda source: source.numeric_raw_severity)
        return sorted_sources[-1].raw_severity, sorted_sources[-1].numeric_raw_severity

    @property
    def average_source_confidence(self):
        if not self.sources:
            return "N/A"

        numerical_confidences = []
        for source in self.sources:
            try:
                if source.str_raw_confidence_score:
                    numerical_confidences.append(int(source.str_raw_confidence_score))
            except:
                if source.numeric_raw_confidence_score:
                    numerical_confidences.append(source.numeric_raw_confidence_score)

        if not numerical_confidences:
            return "N/A"

        avg_confidence = sum(numerical_confidences) / len(numerical_confidences)
        return IOCDetail.avg_confidnce_to_ui(int(avg_confidence))

    @staticmethod
    def avg_confidnce_to_ui(avg_confidence):
        if avg_confidence in range(1, 46):
            return "Low"
        elif avg_confidence in range(46, 76):
            return "Medium"
        elif avg_confidence in range(76, 101):
            return "High"
        else:
            return "N/A"


class Asset(object):
    def __init__(self, raw_data, hostname=None, ip_address=None, first_seen_artifact_time=None, last_seen_artifact_time=None, **kwargs):
        self.raw_data = raw_data
        self.hostname = hostname
        self.ip_address = ip_address
        self.first_seen_artifact_time = first_seen_artifact_time
        self.last_seen_artifact_time = last_seen_artifact_time

        try:
            self.first_seen_artifact_time_ms = convert_string_to_unix_time(self.first_seen_artifact_time)
        except Exception:
            self.first_seen_time_ms = 1

        try:
            self.last_seen_artifact_time_ms = convert_string_to_unix_time(self.last_seen_artifact_time)
        except Exception:
            self.ioc_ingest_time_ms = 1

    def as_json(self):
        return self.raw_data

    def as_csv(self):
        return {
            "Hostname": self.hostname,
            "IP Address": self.ip_address,
            "First Seen Artifact": self.first_seen_artifact_time,
            "Last Seen Artifact": self.last_seen_artifact_time
        }


class Event(object):
    def __init__(self, raw_data, event_type, product_name, timestamp):
        self.raw_data = raw_data
        self.event_type = event_type
        self.product_name = product_name
        self.timestamp = timestamp

    @property
    def get_urls_list(self):
        urls = [self.raw_data.get("target", {}).get("url")]

        return [u for u in urls if u]

    @property
    def get_hashes_list(self):
        hashes = [self.raw_data.get("target", {}).get("file", {}).get("md5"),
                  self.raw_data.get("target", {}).get("file", {}).get("sha1"),
                  self.raw_data.get("target", {}).get("file", {}).get("sha256")]

        return [h for h in hashes if h]

    @property
    def get_ips_list(self):
        ips = []

        ips.extend(self.raw_data.get("target", {}).get("ip", []))
        ips.extend(self.raw_data.get("target", {}).get("asset", {}).get("ip", []))
        ips.extend(self.raw_data.get("src", {}).get("ip", []))
        ips.extend(self.raw_data.get("src", {}).get("asset", {}).get("ip", []))
        ips.extend(self.raw_data.get("principal", {}).get("ip", []))
        ips.extend(self.raw_data.get("principal", {}).get("asset", {}).get("ip", []))

        return ips

    @property
    def get_hostnames_list(self):
        hostnames = [self.raw_data.get("target", {}).get("hostname"),
                     self.raw_data.get("target", {}).get("asset", {}).get("hostname"),
                     self.raw_data.get("principal", {}).get("asset", {}).get("hostname"),
                     self.raw_data.get("principal", {}).get("hostname"), self.raw_data.get("src", {}).get("hostname")]

        return [h for h in hostnames if h]

    @property
    def get_str_processes_list(self):
        processes = [self.raw_data.get("target", {}).get("process", {}).get("file", {}).get("full_path"),
                     self.raw_data.get("target", {}).get("parent_process", {}).get("file", {}).get(
                         "full_path")]

        return [p for p in processes if p]

    @property
    def get_int_processes_list(self):
        processes = [self.raw_data.get("target", {}).get("process", {}).get("pid"),
                     self.raw_data.get("target", {}).get("process", {}).get("parent_pid"),
                     self.raw_data.get("target", {}).get("parent_process", {}).get("pid")]

        return [p for p in processes if p]

    @property
    def get_subjects_list(self):
        subjects = [self.raw_data.get("network", {}).get("email", {}).get("subject")]

        return [s for s in subjects if s]

    @property
    def get_emails_list(self):
        emails = []
        emails.extend(self.raw_data.get("network", {}).get("email", {}).get("to", []))
        emails.extend(self.raw_data.get("network", {}).get("email", {}).get("cc", []))
        emails.extend(self.raw_data.get("network", {}).get("email", {}).get("bcc", []))
        emails.extend([self.raw_data.get("network", {}).get("email", {}).get("from")])

        return [e for e in emails if e]

    @property
    def get_users_list(self):
        users = [self.raw_data.get("principal", {}).get("user", {}).get("user_display_name"),
                 self.raw_data.get("src", {}).get("user", {}).get("user_display_name"),
                 self.raw_data.get("target", {}).get("user", {}).get("user_display_name")]

        return [u for u in users if u]

    @property
    def get_all_entities(self):
        return self.get_users_list + self.get_emails_list + self.get_subjects_list + self.get_str_processes_list + \
               self.get_int_processes_list + self.get_hostnames_list + self.get_ips_list + self.get_hashes_list + \
               self.get_urls_list


class Alert(object):
    class AlertInfo(object):
        def __init__(self, raw_data, name=None, sourceProduct=None, severity=None, timestamp=None,
                     rawLog=None, uri=None, alert_type=None, fallback_severity=None, **kwargs):
            self.raw_data = raw_data
            self.flat_raw_data = dict_to_flat(rename_dict_key(self.raw_data, "udmEvent", "event"))
            self.name = name
            self.source_product = sourceProduct
            self.severity = str(severity).lower() if severity else None
            self.timestamp = timestamp
            self.raw_log = rawLog
            self.uri = uri
            self.id = generate_hash(json.dumps(self.raw_data))
            self.product_name = self.raw_data.get("udmEvent", {}).get("metadata", {}).get("productName")
            self.product_event_type = self.raw_data.get("udmEvent", {}).get("metadata", {}).get("productEventType")
            self.alert_type = alert_type
            self.alert_main_type = consts.EXTERNAL_ALERT_TYPE
            self.fallback_severity = fallback_severity
            self.unified_siemplify_severity = self.get_unified_siemplify_severity or \
                                              consts.SIEMPLIFY_SEVERITIES.get(
                                                  self.fallback_severity.lower()) if self.fallback_severity else None

            try:
                self.timestamp_ms = convert_string_to_unix_time(self.timestamp)
            except Exception:
                self.timestamp_ms = 1

        @property
        def siemplify_severity(self):
            return consts.SIEMPLIFY_SEVERITIES.get(self.severity, -1)

        @property
        def get_unified_siemplify_severity(self):
            return consts.SIEMPLIFY_SEVERITIES.get(self.raw_data.get("severity").lower()) \
                if self.raw_data.get("severity") and self.raw_data.get("severity") != consts.NOT_ASSIGNED else None

        def as_alert_info(self, hostname, events, environment_common, start_time=None, end_time=None):
            """
            Create an AlertInfo out of the current finding
            :param hostname: {str} The hostname of the asset to which this alert info belongs
            :param events: {list} List of the events of the alert info
            :param environment_common: {EnvironmentHandle} The environment common object for fetching the environment
            :param start_time: {int} The start time of the AlertInfo (optional).
            :param end_time: {int} The end time of the AlertInfo (optional).
            :return: {AlertInfo} The created AlertInfo object
            """
            alert_info = AlertInfo()
            alert_info.environment = environment_common.get_environment(dict_to_flat(self.raw_data))
            alert_info.ticket_id = str(uuid.uuid4())
            alert_info.display_id = str(uuid.uuid4())
            alert_info.name = f"{self.name} for {hostname}"
            alert_info.description = f"{self.name} for {hostname}"
            alert_info.device_vendor = consts.VENDOR
            alert_info.device_product = f"{self.source_product} for Google Chronicle"
            alert_info.priority = self.siemplify_severity
            alert_info.rule_generator = "Asset"
            alert_info.start_time = start_time or self.timestamp_ms
            alert_info.end_time = end_time or self.timestamp_ms
            alert_info.events = events
            return alert_info

        def as_unified_alert_info(self, alert_info, environment_common, device_product_field):
            """
            Prepare AlertInfo for unified connector
            :param alert_info: {AlertInfo} AlertInfo object
            :param environment_common: {EnvironmentHandle} environment common object for fetching the environment
            :param device_product_field: {str} key to use for device product extraction
            :return: {AlertInfo} created AlertInfo object
            """
            alert_info.environment = environment_common.get_environment(self.flat_raw_data)
            alert_info.ticket_id = self.id
            alert_info.display_id = str(uuid.uuid4())
            alert_info.name = self.name
            alert_info.description = self.get_description()
            alert_info.device_vendor = consts.UNIFIED_CONNECTOR_DEVICE_VENDOR
            alert_info.priority = self.unified_siemplify_severity
            alert_info.rule_generator = f"EXTERNAL Alert: {self.name}"
            alert_info.start_time = self.timestamp_ms
            alert_info.end_time = self.timestamp_ms
            alert_info.events = self.unified_events
            alert_info.extensions = {
                "alert_type": consts.ALERT_TYPE_NAMES.get(consts.ALERT_TYPES.get("external")),
                "alert_name": self.name,
                "product_name": self.product_name,
            }
            alert_info.device_product = next((event.get(device_product_field) for event in alert_info.events
                                              if event.get(device_product_field)), None) \
                                        or consts.UNIFIED_CONNECTOR_DEVICE_PRODUCT

            return alert_info

        def as_event(self):
            return dict_to_flat(self.raw_data)

        @property
        def unified_events(self):
            raw_alert_data = deepcopy(self.raw_data)
            emails = raw_alert_data.get("udmEvent", {}).get("network", {}).get("email", {})

            if emails.get("to") or emails.get("cc") or emails.get("bcc"):
                emails["to"] = list(set(emails.get("to", []) + emails.get("cc", []) + emails.get("bcc", [])))
                emails.pop("cc", None)
                emails.pop("bcc", None)

            additional_info = {
                "alert_type": consts.ALERT_TYPE_NAMES.get(consts.ALERT_TYPES.get('external')),
                "event_type": raw_alert_data.get("udmEvent", {}).get("metadata", {}).get("eventType"),
                "event_category": get_prefix_from_string(
                    raw_alert_data.get("udmEvent", {}).get("metadata", {}).get("eventType")
                )
            }

            events = separate_data_per_multiple_values_keys(
                rename_dict_key(raw_alert_data, "udmEvent", "event"),
                consts.EXTERNAL_MULTIPLE_VALUES_NESTED_KEYS,
                additional_info
            )

            return [dict_to_flat(event) for event in events]

        def get_description(self):
            return utils.convert_list_to_comma_string(
                [item.get("description", "") for item in self.raw_data.get("udmEvent", {}).get("securityResult", [])]
            )

        @property
        def hash_id(self):
            temp_data = deepcopy(self.raw_data)
            temp_data.pop("uri", None)
            return hashlib.md5(json.dumps(temp_data, sort_keys=True).encode("utf8")).hexdigest()

        @property
        def get_unique_product_name(self):
            return self.product_name

        @property
        def get_product_names_list(self):
            return [self.product_name]

        @property
        def get_urls_list(self):
            urls = [self.raw_data.get("udmEvent", {}).get("target", {}).get("url")]
            return [u for u in urls if u]

        @property
        def get_hashes_list(self):
            hashes = [self.raw_data.get("udmEvent", {}).get("target", {}).get("file", {}).get("md5"),
                      self.raw_data.get("udmEvent", {}).get("target", {}).get("file", {}).get("sha1"),
                      self.raw_data.get("udmEvent", {}).get("target", {}).get("file", {}).get("sha256")]
            return [h for h in hashes if h]

        @property
        def get_ips_list(self):
            ips = self.raw_data.get("udmEvent", {}).get("target", {}).get("ip", []) + \
                  self.raw_data.get("udmEvent", {}).get("target", {}).get("asset", {}).get("ip", []) + \
                  self.raw_data.get("udmEvent", {}).get("src", {}).get("ip", []) + \
                  self.raw_data.get("udmEvent", {}).get("src", {}).get("asset", {}).get("ip", []) + \
                  self.raw_data.get("udmEvent", {}).get("principal", {}).get("ip", []) + \
                  self.raw_data.get("udmEvent", {}).get("principal", {}).get("asset", {}).get("ip", [])

            return list(set(ips))

        @property
        def get_hostnames_list(self):
            hostnames = list({self.raw_data.get("udmEvent", {}).get("target", {}).get("hostname"),
                             self.raw_data.get("udmEvent", {}).get("target", {}).get("asset", {}).get("hostname"),
                             self.raw_data.get("udmEvent", {}).get("principal", {}).get("hostname"),
                             self.raw_data.get("udmEvent", {}).get("principal", {}).get("asset", {}).get("hostname"),
                             self.raw_data.get("udmEvent", {}).get("src", {}).get("hostname")})
            return [h for h in hostnames if h]

        @property
        def get_processes_list(self):
            processes = list({self.raw_data.get("udmEvent", {}).get("target", {}).get("process", {}).get("file", {}).get(
                            "full_path"),
                         self.raw_data.get("udmEvent", {}).get("target", {}).get("parent_process", {}).get("file", {}).get(
                            "full_path")})
            return [p for p in processes if p]

        @property
        def get_subjects_list(self):
            subject = self.raw_data.get("udmEvent", {}).get("network", {}).get("email", {}).get("subject")
            subjects = subject if isinstance(subject, list) else [subject]
            return [s for s in subjects if s]

        @property
        def get_emails_list(self):
            emails = self.raw_data.get("udmEvent", {}).get("network", {}).get("email", {}).get("to", []) + \
                  self.raw_data.get("udmEvent", {}).get("network", {}).get("email", {}).get("cc", []) + \
                  self.raw_data.get("udmEvent", {}).get("network", {}).get("email", {}).get("bcc", []) + \
                  [self.raw_data.get("udmEvent", {}).get("network", {}).get("email", {}).get("from")] + \
                  self.raw_data.get("udmEvent", {}).get("principal", {}).get("user", {}).get("emailAddresses", []) + \
                  self.raw_data.get("udmEvent", {}).get("src", {}).get("user", {}).get("emailAddresses", []) + \
                  self.raw_data.get("udmEvent", {}).get("target", {}).get("user", {}).get("emailAddresses", [])

            return list(set([e for e in emails if e]))

        @property
        def get_users_list(self):
            users = list({self.raw_data.get("udmEvent", {}).get("principal", {}).get("user", {}).get("user_display_name"),
                         self.raw_data.get("udmEvent", {}).get("src", {}).get("user", {}).get("user_display_name"),
                         self.raw_data.get("udmEvent", {}).get("target", {}).get("user", {}).get("user_display_name"),
                          self.raw_data.get("udmEvent", {}).get("principal", {}).get("user", {}).get("userid"),
                          self.raw_data.get("udmEvent", {}).get("src", {}).get("user", {}).get("userid"),
                          self.raw_data.get("udmEvent", {}).get("target", {}).get("user", {}).get("userid")})
            return [u for u in users if u]

        @property
        def get_all_entities(self):
            entities = self.get_users_list + self.get_emails_list + self.get_subjects_list + self.get_processes_list + \
                   self.get_hostnames_list + self.get_ips_list + self.get_hashes_list + self.get_urls_list
            return [e.lower() for e in entities]

    def __init__(self, raw_data, hostname=None, ip_address=None, mac=None, alert_infos=None, **kwargs):
        self.raw_data = raw_data
        self.hostname = hostname
        self.ip_address = ip_address
        self.mac = mac
        self.alert_infos = alert_infos or []

    @property
    def hash_id(self):
        # Use the hash ids of the alert infos to create a unique info dict for the alert itself
        # and MD5 the json form of the dict
        temp_data = {
            "hostname": self.hostname,
            "alert_info_ids": [alert_info.hash_id for alert_info in self.alert_infos]
        }
        return hashlib.md5(json.dumps(temp_data, sort_keys=True).encode("utf8")).hexdigest()

    @property
    def asset(self):
        return self.hostname or self.ip_address or self.mac

    @property
    def start_time(self):
        if not self.alert_infos:
            return 0

        sorted_alert_infos = sorted(self.alert_infos, key=lambda alert_info: alert_info.timestamp_ms)
        return sorted_alert_infos[0].timestamp_ms

    @property
    def end_time(self):
        if not self.alert_infos:
            return 0

        sorted_alert_infos = sorted(self.alert_infos, key=lambda alert_info: alert_info.timestamp_ms)
        return sorted_alert_infos[-1].timestamp_ms


class Detection(object):
    def __init__(self, raw_data, identifier, rule_id, alert_state, name, created_time, start_time, end_time, detections,
                 collection_elements, rule_type, url_back_to_product, fallback_severity=None):
        self.raw_data = raw_data
        self.uuid = str(uuid.uuid4())
        self.flat_raw_data = dict_to_flat(raw_data)
        self.id = identifier
        self.rule_id = rule_id
        self.alert_state = alert_state
        self.name = name
        self.created_time = created_time
        self.timestamp = convert_string_to_unix_time(created_time)
        self.start_time = start_time
        self.end_time = end_time
        self.detections = detections
        self.collection_elements = collection_elements
        self.fallback_severity = fallback_severity
        self.siemplify_severity = self.get_siemplify_severity or (consts.SIEMPLIFY_SEVERITIES.get(
            self.fallback_severity.lower()) if self.fallback_severity else None)
        self.alert_main_type = consts.RULE_ALERT_TYPE
        self.rule_type = rule_type
        self.parsed_url_back_to_product = urlparse(url_back_to_product)

    def as_unified_alert_info(self, alert_info, environment_common, device_product_field):
        alert_info.ticket_id = self.id
        alert_info.display_id = f"{consts.RULE_ALERT_PREFIX}_{self.id}__{self.rule_type}"
        alert_info.name = self.name
        alert_info.description = self.get_description()
        alert_info.device_vendor = consts.UNIFIED_CONNECTOR_DEVICE_VENDOR
        alert_info.priority = self.siemplify_severity
        alert_info.rule_generator = self.name
        alert_info.start_time = convert_string_to_unix_time(self.start_time)
        alert_info.end_time = convert_string_to_unix_time(self.end_time)
        alert_info.events = self.get_unified_events()
        alert_info.environment = environment_common.get_environment(alert_info.events[0] if alert_info.events else {})
        alert_info.extensions = {
            "alert_type": consts.ALERT_TYPE_NAMES.get(consts.ALERT_TYPES.get("rule")),
            "rule_id": self.rule_id,
            "product_name": self.get_product_name,
            "chronicle_alert_type": self.rule_type,
            "ui_base_link": self.parsed_url_back_to_product.scheme + "://" + self.parsed_url_back_to_product.netloc
        }
        alert_info.device_product = next((event.get(device_product_field) for event in alert_info.events
                                          if event.get(device_product_field)), None) \
                                    or consts.UNIFIED_CONNECTOR_DEVICE_PRODUCT
        try:
            alert_info.source_system_url = self.parsed_url_back_to_product.scheme + "://" + \
                                           self.parsed_url_back_to_product.netloc
            alert_info.source_rule_identifier = self.rule_id
        except:
            pass

        return alert_info

    def get_description(self):
        for detection in self.detections:
            rule_labels = detection.get("ruleLabels", [{}])
            for rule_label in rule_labels:
                if rule_label.get("key") == "description":
                    return rule_label.get("value")

        return ""

    @property
    def get_product_name(self):
        product_names = []

        for collection_element in self.collection_elements:
            for reference in collection_element.get("references", []):
                product_names.append(reference.get("event", {}).get("metadata", {}).get("productName"))

        return utils.convert_list_to_comma_string([product_name for product_name in product_names if product_name]) or ""

    @property
    def get_unique_product_name(self):
        product_names = set()

        for collection_element in self.collection_elements:
            for reference in collection_element.get("references", []):
                product_names.add(reference.get("event", {}).get("metadata", {}).get("productName"))

        return utils.convert_list_to_comma_string([product_name for product_name in product_names if product_name]) or ""

    @property
    def get_product_names_list(self):
        product_names = []

        for collection_element in self.collection_elements:
            for reference in collection_element.get("references", []):
                product_names.append(reference.get("event", {}).get("metadata", {}).get("productName"))

        return product_names

    @property
    def get_siemplify_severity(self):
        # severity for GCTI type of alert
        sorted_detections = sorted(
            self.detections, key=lambda item: consts.GCTI_ALERT_SEVERITY_MAPPING.get(item.get("severity", ""), 0),
            reverse=True
        )

        if sorted_detections and sorted_detections[0].get("severity"):
            return consts.GCTI_ALERT_SEVERITY_MAPPING.get(sorted_detections[0].get("severity"))

        # severity for RULE type of alert
        severity_key = ""

        for detection in self.detections:
            rule_labels = detection.get("ruleLabels", [{}])
            for rule_label in rule_labels:
                if rule_label.get("key") == "severity":
                    severity_key = rule_label.get("value")
                    break

        return consts.SIEMPLIFY_SEVERITIES.get(severity_key.lower(), None)

    def get_unified_events(self):
        alert_data_without_events = deepcopy(self.raw_data)
        references = []
        events = []

        if alert_data_without_events.get("collectionElements"):
            del alert_data_without_events["collectionElements"]

        for collection_element in self.collection_elements:
            references.extend(collection_element.get("references", []))

        for reference in references:
            event_raw_data = {**reference, **alert_data_without_events}
            emails = event_raw_data.get("event", {}).get("network", {}).get("email", {})

            if emails.get("to") or emails.get("cc") or emails.get("bcc"):
                emails["to"] = list(set(emails.get("to", []) + emails.get("cc", []) + emails.get("bcc", [])))
                emails.pop("cc", None)
                emails.pop("bcc", None)

            additional_info = {
                "alert_type": consts.ALERT_TYPE_NAMES.get(consts.ALERT_TYPES.get('rule')),
                "event_type": event_raw_data.get("event", {}).get("metadata", {}).get("eventType") or
                              event_raw_data.get("entity", {}).get("metadata", {}).get("entityType"),
                "event_category": get_prefix_from_string(
                    event_raw_data.get("event", {}).get("metadata", {}).get("eventType", "")
                ) or get_prefix_from_string(
                    event_raw_data.get("entity", {}).get("metadata", {}).get("entityType", "")
                )
            }

            events.extend(separate_data_per_multiple_values_keys(event_raw_data, consts.RULE_MULTIPLE_VALUES_NESTED_KEYS,
                                                                 additional_info))

        return [fix_key_value_pair(dict_to_flat(event)) for event in events]

    @property
    def get_urls_list(self):
        urls = []

        for collection_element in self.collection_elements:
            for reference in collection_element.get("references", []):
                urls.append(reference.get("event", {}).get("target", {}).get("url"))

        return [u for u in urls if u]

    @property
    def get_hashes_list(self):
        hashes = []

        for collection_element in self.collection_elements:
            for reference in collection_element.get("references", []):
                hashes.append(reference.get("event", {}).get("target", {}).get("file", {}).get("md5"))
                hashes.append(reference.get("event", {}).get("target", {}).get("file", {}).get("sha1"))
                hashes.append(reference.get("event", {}).get("target", {}).get("file", {}).get("sha256"))

        return [h for h in hashes if h]

    @property
    def get_ips_list(self):
        ips = []

        for collection_element in self.collection_elements:
            for reference in collection_element.get("references", []):
                ips.extend(reference.get("event", {}).get("target", {}).get("ip", []))
                ips.extend(reference.get("event", {}).get("target", {}).get("asset", {}).get("ip", []))
                ips.extend(reference.get("event", {}).get("src", {}).get("ip", []))
                ips.extend(reference.get("event", {}).get("src", {}).get("asset", {}).get("ip", []))
                ips.extend(reference.get("event", {}).get("principal", {}).get("ip", []))
                ips.extend(reference.get("event", {}).get("principal", {}).get("asset", {}).get("ip", []))

        return ips

    @property
    def get_hostnames_list(self):
        hostnames = []

        for collection_element in self.collection_elements:
            for reference in collection_element.get("references", []):
                hostnames.append(reference.get("event", {}).get("target", {}).get("hostname"))
                hostnames.append(reference.get("event", {}).get("target", {}).get("asset", {}).get("hostname"))
                hostnames.append(reference.get("event", {}).get("principal", {}).get("asset", {}).get("hostname"))
                hostnames.append(reference.get("event", {}).get("principal", {}).get("hostname"))
                hostnames.append(reference.get("event", {}).get("src", {}).get("hostname"))

        return [h for h in hostnames if h]

    @property
    def get_processes_list(self):
        processes = []

        for collection_element in self.collection_elements:
            for reference in collection_element.get("references", []):
                processes.append(reference.get("event", {}).get("target", {}).get("process", {}).get("file", {}).get("full_path"))
                processes.append(reference.get("event", {}).get("target", {}).get("parent_process", {}).get("file", {}).get("full_path"))

        return [p for p in processes if p]

    @property
    def get_subjects_list(self):
        subjects = []

        for collection_element in self.collection_elements:
            for reference in collection_element.get("references", []):
                subject = reference.get("event", {}).get("network", {}).get("email", {}).get("subject")
                if isinstance(subject, list):
                    subjects.extend(subject)
                else:
                    subjects.append(subject)

        return [s for s in subjects if s]

    @property
    def get_emails_list(self):
        emails = []

        for collection_element in self.collection_elements:
            for reference in collection_element.get("references", []):
                emails.extend(reference.get("event", {}).get("network", {}).get("email", {}).get("to", []))
                emails.extend(reference.get("event", {}).get("network", {}).get("email", {}).get("cc", []))
                emails.extend(reference.get("event", {}).get("network", {}).get("email", {}).get("bcc", []))
                emails.extend([reference.get("event", {}).get("network", {}).get("email", {}).get("from")])
                emails.extend(reference.get("event", {}).get("principal", {}).get("user", {}).get("emailAddresses", []))
                emails.extend(reference.get("event", {}).get("src", {}).get("user", {}).get("emailAddresses", []))
                emails.extend(reference.get("event", {}).get("target", {}).get("user", {}).get("emailAddresses", []))

        return [e for e in emails if e]

    @property
    def get_users_list(self):
        users = []

        for collection_element in self.collection_elements:
            for reference in collection_element.get("references", []):
                users.append(reference.get("event", {}).get("principal", {}).get("user", {}).get("user_display_name"))
                users.append(reference.get("event", {}).get("src", {}).get("user", {}).get("user_display_name"))
                users.append(reference.get("event", {}).get("target", {}).get("user", {}).get("user_display_name"))
                users.append(reference.get("event", {}).get("principal", {}).get("user", {}).get("userid"))
                users.append(reference.get("event", {}).get("src", {}).get("user", {}).get("userid"))
                users.append(reference.get("event", {}).get("target", {}).get("user", {}).get("userid"))

        return [u for u in users if u]

    @property
    def get_all_entities(self):
        entities = self.get_users_list + self.get_emails_list + self.get_subjects_list + self.get_processes_list + \
               self.get_hostnames_list + self.get_ips_list + self.get_hashes_list + self.get_urls_list
        return [e.lower() for e in entities]


class ChronicleCase(object):
    def __init__(self, raw_data, id=None, external_id=None, priority=None, status=None, environment=None, stage=None,
                 has_failed=False, tracking_time=None, display_name=None):
        self.raw_data = raw_data
        self.id = id
        self.external_id = external_id if external_id != "None" else ""
        self.priority = priority
        self.status = status
        self.environment = environment
        self.stage = stage
        self.has_failed = has_failed
        self.tracking_time = tracking_time
        self.display_name = display_name


class ChronicleAlert(object):
    def __init__(self, raw_data, id=None, ticket_id=None, creation_time=None, priority=None, status=None,
                 environment=None, comment=None, has_failed=False, tracking_time=None, reason=None, root_cause=None,
                 case_id=None, group_id=None, usefulness=None):
        self.raw_data = raw_data
        self.id = id
        self.ticket_id = ticket_id
        self.creation_time = creation_time
        self.priority = priority
        self.status = status
        self.environment = environment
        self.comment = comment
        self.has_failed = has_failed
        self.tracking_time = tracking_time
        self.reason = reason
        self.root_cause = root_cause
        self.case_id = case_id
        self.group_id = group_id
        self.usefulness = usefulness


class CaseMetadata(object):
    def __init__(self, raw_data, id=None, tracking_time=None):
        self.raw_data = raw_data
        self.id = id
        self.tracking_time = tracking_time


class AlertMetadata(object):
    def __init__(self, raw_data, group_id=None, tracking_time=None):
        self.raw_data = raw_data
        self.group_id = group_id
        self.tracking_time = tracking_time

class MultipartResponsePart(object):
    def __init__(self, body, headers, status_code, encoding="utf-8"):
        self._body = body
        self._headers = headers
        self._status_code = status_code
        self._encoding = encoding

    @property
    def content(self) -> bytes:
        return self._body

    @property
    def text(self) -> str:
        return self._body.decode(self._encoding)

    @property
    def headers(self) -> dict:
        return self._headers

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def encoding(self) -> str:
        return self._encoding

    def json(self):
        return json.loads(self._body)


class UdmQueryEvent:
    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data
