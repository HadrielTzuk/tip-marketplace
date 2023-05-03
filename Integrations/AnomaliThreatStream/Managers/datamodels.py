import copy
from utils import convert_string_to_unix_time, as_html_link
from constants import INDICATOR_STATUSES, SEVERITIES_ORDER, SEVERITIES_TO_SIEMPLIFY_SEVERITIES, ENRICHMENT_PREFIX, \
    URL_INDICATOR_TYPE, DOMAIN_INDICATOR_TYPE, EMAIL_INDICATOR_TYPE, IP_INDICATOR_TYPE, SEVERITIES_COLORS, ORANGE, \
    GREEN, DEFAULT_INSIGHT_PLACEHOLDER, IP_INSIGHT_HTML_TEMPLATE, URL_INSIGHT_HTML_TEMPLATE, \
    DOMAIN_INSIGHT_HTML_TEMPLATE, FILEHASH_INSIGHT_HTML_TEMPLATE, EMAIL_INSIGHT_HTML_TEMPLATE, APPROVED_JOB_STATUS, \
    NOT_ASSIGNED
from TIPCommon import add_prefix_to_dict, dict_to_flat


class Indicator(object):
    """
    Threat Fuse indicator
    """
    def __init__(self, raw_data, source_created=None, status=None, itype=None, type=None, value=None, confidence=None,
                 id=None, source=None, tags=None, threatscore=None, modified_ts=None, created_ts=None, threat_type=None,
                 expiration_ts=None, is_anonymous=None, tlp=None, subtype=None, resource_uri=None, web_root=None,
                 severity=None, ip=None, feed_id=None, uuid=None, retina_confidence=None, trusted_circle_ids=None,
                 latitude=None, longitude=None, source_reported_confidence=None, org=None, asn=None, country=None,
                 registrant_address=None, registration_created=None, registration_updated=None, **kwargs):
        self.raw_data = raw_data
        self.web_root = web_root
        self.source_created = source_created
        self.status = status
        self.itype = itype
        self.type = type
        self.value = value
        self.confidence = confidence
        self.severity = severity
        self.id = id
        self.source = source
        self.tags = tags or []  # list of dictionaries. Each dictionary has key:value representing a tag
        self.threat_score = threatscore
        self.modified_ts = modified_ts  # UTC time
        self.created_ts = created_ts  # UTC time
        self.expiration_ts = expiration_ts  # UTC time
        self.is_anonymous = is_anonymous
        self.tlp = tlp
        self.subtype = subtype
        self.resource_uri = resource_uri
        self.ip = ip
        self.feed_id = feed_id
        self.uuid = uuid
        self.retina_confidence = retina_confidence
        self.trusted_circle_ids = trusted_circle_ids
        self.latitude = latitude
        self.longitude = longitude
        self.source_reported_confidence = source_reported_confidence
        self.org = org
        self.asn = asn
        self.country = country
        self.threat_score = threatscore
        self.threat_type = threat_type
        self.registrant_address = registrant_address
        self.registration_created = registration_created
        self.registration_updated = registration_updated

        if modified_ts:
            self.modified_ts_ms = convert_string_to_unix_time(self.modified_ts)
        else:
            self.modified_ts_ms = 1

    @property
    def is_active(self):
        return self.status == INDICATOR_STATUSES.get('Active')

    @property
    def is_inactive(self):
        return self.status == INDICATOR_STATUSES.get('Inactive')

    @property
    def is_false_positive(self):
        return self.status == INDICATOR_STATUSES.get('False Positive')

    @property
    def numeric_severity(self):
        return SEVERITIES_ORDER.get(str(self.severity).lower(), 0)

    @property
    def siemplify_severity(self):
        return SEVERITIES_TO_SIEMPLIFY_SEVERITIES.get(str(self.severity).lower(), 0)

    def as_enrichment(self, prefix=ENRICHMENT_PREFIX):
        enrichment_data = {
            "id": self.id,
            "status": self.status,
            "itype": self.itype,
            "expiration_time": self.expiration_ts,
            "ip": self.ip,
            "feed_id": self.feed_id,
            "uuid": self.uuid,
            "retina_confidence": self.retina_confidence,
            "trusted_circle_ids": ", ".join([str(circle_id) for circle_id in self.trusted_circle_ids])
            if self.trusted_circle_ids else "",
            "source": self.source,
            "latitude": self.latitude,
            "type": self.type,
            "tags": ", ".join(tag.name for tag in self.tags) if self.tags else "",
            "threat_score": self.threat_score,
            "source_confidence": self.source_reported_confidence,
            "modification_time": self.modified_ts,
            "org_name": self.org,
            "asn": self.asn,
            "creation_time": self.created_ts,
            "tlp": self.tlp,
            "country": self.country,
            "longitude": self.longitude,
            "severity": self.severity,
            "subtype": self.subtype,
            "report": self.report_link,
        }
        enrichment_data = {k: v for k, v in enrichment_data.items() if v not in (None, '')}

        if prefix:
            return add_prefix_to_dict(dict_to_flat(enrichment_data), prefix)

        return dict_to_flat(enrichment_data)

    @property
    def report_link(self):
        if self.type in [URL_INDICATOR_TYPE, DOMAIN_INDICATOR_TYPE, EMAIL_INDICATOR_TYPE, IP_INDICATOR_TYPE]:
            return f"{self.web_root}/detail/{self.type}/{self.value}"

        return f"{self.web_root}/detail/hash/{self.value}"

    def as_json(self):
        data = copy.deepcopy(self.raw_data)
        data["report_link"] = self.report_link
        return data

    def as_event(self):
        data = copy.deepcopy(self.raw_data)
        data[self.type] = self.value
        return dict_to_flat(data)


class Tag(object):
    """
    Threat Fuse Tag
    """

    def __init__(self, raw_data, id=None, name=None, **kwargs):
        self.raw_data = raw_data
        self.id = id
        self.name = name


class IndicatorsGroup(object):
    """
    Object for INTERNAL USE ONLY - to match indicators with the entity that they were fetched for
    """

    def __init__(self, entity, indicators=None):
        self.entity = entity
        self.indicators = indicators or []

    def add_indicator(self, indicator):
        self.indicators.append(indicator)

    @property
    def inactive_indicators_count(self):
        return len([indicator for indicator in self.indicators if indicator.is_inactive])

    @property
    def false_positive_indicators_count(self):
        return len([indicator for indicator in self.indicators if indicator.is_false_positive])

    @property
    def latest_indicator(self):
        if not self.indicators:
            return

        return sorted(self.indicators, key=lambda indicator: indicator.modified_ts_ms)[-1]

    @property
    def active_indicators(self):
        return [indicator for indicator in self.indicators if indicator.is_active]

    @property
    def active_indicators_count(self):
        return len(self.active_indicators)

    @property
    def severity(self):
        if self.active_indicators_count > 0:
            return sorted(self.active_indicators, key=lambda indicator: indicator.numeric_severity)[-1].severity

        else:
            return self.latest_indicator.severity

    @property
    def numeric_severity(self):
        if self.active_indicators_count > 0:
            return sorted(self.active_indicators, key=lambda indicator: indicator.numeric_severity)[-1].numeric_severity

        else:
            return self.latest_indicator.numeric_severity

    @property
    def confidence(self):
        if self.active_indicators_count > 0:
            confidences = [indicator.confidence for indicator in self.active_indicators]
            return round(sum(confidences) / len(confidences) + 0.5)

        else:
            return self.latest_indicator.confidence

    @property
    def is_false_positive(self):
        if self.active_indicators_count > 0:
            return False

        else:
            return self.latest_indicator.is_false_positive

    @staticmethod
    def get_merged_attribute(attr_name, indicators):
        return ", ".join(list(set(str(getattr(indicator, attr_name, "")) for indicator in indicators)))

    def as_enrichment(self, prefix=ENRICHMENT_PREFIX):
        if self.active_indicators_count > 0:
            enrichment_indicators = [indicator.as_enrichment(prefix) for indicator in self.active_indicators]

            merged_enrichment = {}
            for key in enrichment_indicators[0].keys():
                merged_enrichment[key] = ", ".join(list(set(
                    str(enrichment_indicator[key]) for enrichment_indicator in enrichment_indicators if
                    enrichment_indicator[key])))

            if prefix:
                merged_enrichment[f"{prefix}_severity"] = self.severity
                merged_enrichment[f"{prefix}_confidence"] = self.confidence

            else:
                merged_enrichment[f"severity"] = self.severity
                merged_enrichment[f"confidence"] = self.confidence

            return merged_enrichment

        else:
            if not self.latest_indicator:
                return {}

            return self.latest_indicator.as_enrichment(prefix)

    def as_csv(self):
        enrichment_data = self.as_enrichment(prefix=None)
        return {k.replace("_", " ").title(): v for k, v in enrichment_data.items()}

    def as_ip_insight(self, intel_details):
        if self.active_indicators_count:
            return IP_INSIGHT_HTML_TEMPLATE.format(
                status=self.get_merged_attribute('status', self.active_indicators),
                severity=self.severity,
                severity_color=SEVERITIES_COLORS.get(self.severity),
                confidence=self.confidence,
                confidence_color=GREEN if self.confidence > 50 else ORANGE,
                asn=self.get_merged_attribute('asn', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                country=self.get_merged_attribute('country', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                virus_total_classification=intel_details.virus_total_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                domain_tools_classification=intel_details.domain_tools_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                google_safe_browsing_classification=intel_details.google_safe_browsing_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                ipvoid_classification=intel_details.ipvoid_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                honeypot_classification=intel_details.honeypot_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                web_of_trust_classification=intel_details.web_of_trust_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                ipvoid_detections=intel_details.ipvoid_detections or DEFAULT_INSIGHT_PLACEHOLDER,
                itype=self.get_merged_attribute('itype', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                threat_type=self.get_merged_attribute('threat_type',
                                                      self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                source=self.get_merged_attribute('source', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                report_link=self.get_merged_attribute('report_link',
                                                      self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
            )

        else:
            return IP_INSIGHT_HTML_TEMPLATE.format(
                status=self.latest_indicator.status,
                severity=self.latest_indicator.severity,
                severity_color=SEVERITIES_COLORS.get(self.latest_indicator.severity),
                confidence=self.latest_indicator.confidence,
                confidence_color=GREEN if self.latest_indicator.confidence > 50 else ORANGE,
                asn=self.latest_indicator.asn or DEFAULT_INSIGHT_PLACEHOLDER,
                country=self.latest_indicator.country or DEFAULT_INSIGHT_PLACEHOLDER,
                virus_total_classification=intel_details.virus_total_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                domain_tools_classification=intel_details.domain_tools_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                google_safe_browsing_classification=intel_details.google_safe_browsing_classification
                                                    or DEFAULT_INSIGHT_PLACEHOLDER,
                ipvoid_classification=intel_details.ipvoid_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                honeypot_classification=intel_details.honeypot_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                web_of_trust_classification=intel_details.web_of_trust_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                ipvoid_detections=intel_details.ipvoid_detections or DEFAULT_INSIGHT_PLACEHOLDER,
                itype=self.latest_indicator.itype or DEFAULT_INSIGHT_PLACEHOLDER,
                threat_type=self.latest_indicator.threat_type or DEFAULT_INSIGHT_PLACEHOLDER,
                source=self.latest_indicator.source or DEFAULT_INSIGHT_PLACEHOLDER,
                report_link=self.latest_indicator.report_link or DEFAULT_INSIGHT_PLACEHOLDER
            )

    def as_url_insight(self, intel_details):
        if self.active_indicators_count:
            return URL_INSIGHT_HTML_TEMPLATE.format(
                status=self.get_merged_attribute('status', self.active_indicators),
                severity=self.severity,
                severity_color=SEVERITIES_COLORS.get(self.severity),
                confidence=self.confidence,
                confidence_color=GREEN if self.confidence > 50 else ORANGE,
                ip=self.get_merged_attribute('ip', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                org=self.get_merged_attribute('org', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                country=self.get_merged_attribute('country', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                virus_total_classification=intel_details.virus_total_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                domain_tools_classification=intel_details.domain_tools_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                google_safe_browsing_classification=intel_details.google_safe_browsing_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                ipvoid_classification=intel_details.ipvoid_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                honeypot_classification=intel_details.honeypot_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                web_of_trust_classification=intel_details.web_of_trust_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                ipvoid_detections=intel_details.ipvoid_detections or DEFAULT_INSIGHT_PLACEHOLDER,
                itype=self.get_merged_attribute('itype', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                threat_type=self.get_merged_attribute('threat_type',
                                                      self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                source=self.get_merged_attribute('source', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                report_link=self.get_merged_attribute('report_link',
                                                      self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
            )

        else:
            return URL_INSIGHT_HTML_TEMPLATE.format(
                status=self.latest_indicator.status,
                severity=self.latest_indicator.severity,
                severity_color=SEVERITIES_COLORS.get(self.latest_indicator.severity),
                confidence=self.latest_indicator.confidence,
                confidence_color=GREEN if self.latest_indicator.confidence > 50 else ORANGE,
                ip=self.latest_indicator.ip or DEFAULT_INSIGHT_PLACEHOLDER,
                country=self.latest_indicator.country or DEFAULT_INSIGHT_PLACEHOLDER,
                org=self.latest_indicator.org or DEFAULT_INSIGHT_PLACEHOLDER,
                virus_total_classification=intel_details.virus_total_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                domain_tools_classification=intel_details.domain_tools_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                google_safe_browsing_classification=intel_details.google_safe_browsing_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                ipvoid_classification=intel_details.ipvoid_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                honeypot_classification=intel_details.honeypot_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                web_of_trust_classification=intel_details.web_of_trust_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                ipvoid_detections=intel_details.ipvoid_detections or DEFAULT_INSIGHT_PLACEHOLDER,
                itype=self.latest_indicator.itype or DEFAULT_INSIGHT_PLACEHOLDER,
                threat_type=self.latest_indicator.threat_type or DEFAULT_INSIGHT_PLACEHOLDER,
                source=self.latest_indicator.source or DEFAULT_INSIGHT_PLACEHOLDER,
                report_link=self.latest_indicator.report_link or DEFAULT_INSIGHT_PLACEHOLDER
            )

    def as_domain_insight(self, intel_details):
        if self.active_indicators_count:
            return DOMAIN_INSIGHT_HTML_TEMPLATE.format(
                status=self.get_merged_attribute('status', self.active_indicators),
                severity=self.severity,
                severity_color=SEVERITIES_COLORS.get(self.severity),
                confidence=self.confidence,
                confidence_color=GREEN if self.confidence > 50 else ORANGE,
                ip=self.get_merged_attribute('ip', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                org=self.get_merged_attribute('org', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                country=self.get_merged_attribute('country', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                registrant_address=self.get_merged_attribute('registrant_address',
                                                             self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                registration_created=self.get_merged_attribute('registration_created',
                                                               self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                registration_updated=self.get_merged_attribute('registration_updated',
                                                               self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                virus_total_classification=intel_details.virus_total_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                domain_tools_classification=intel_details.domain_tools_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                google_safe_browsing_classification=intel_details.google_safe_browsing_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                ipvoid_classification=intel_details.ipvoid_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                honeypot_classification=intel_details.honeypot_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                web_of_trust_classification=intel_details.web_of_trust_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                ipvoid_detections=intel_details.ipvoid_detections or DEFAULT_INSIGHT_PLACEHOLDER,
                itype=self.get_merged_attribute('itype', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                threat_type=self.get_merged_attribute('threat_type', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                source=self.get_merged_attribute('source', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                report_link=self.get_merged_attribute('report_link', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
            )

        else:
            return DOMAIN_INSIGHT_HTML_TEMPLATE.format(
                status=self.latest_indicator.status,
                severity=self.latest_indicator.severity,
                severity_color=SEVERITIES_COLORS.get(self.latest_indicator.severity),
                confidence=self.latest_indicator.confidence,
                confidence_color=GREEN if self.latest_indicator.confidence > 50 else ORANGE,
                ip=self.latest_indicator.ip or DEFAULT_INSIGHT_PLACEHOLDER,
                country=self.latest_indicator.country or DEFAULT_INSIGHT_PLACEHOLDER,
                org=self.latest_indicator.org or DEFAULT_INSIGHT_PLACEHOLDER,
                registrant_address=self.latest_indicator.registrant_address or DEFAULT_INSIGHT_PLACEHOLDER,
                registration_updated=self.latest_indicator.registration_updated or DEFAULT_INSIGHT_PLACEHOLDER,
                registration_created=self.latest_indicator.registration_created or DEFAULT_INSIGHT_PLACEHOLDER,
                virus_total_classification=intel_details.virus_total_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                domain_tools_classification=intel_details.domain_tools_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                google_safe_browsing_classification=intel_details.google_safe_browsing_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                ipvoid_classification=intel_details.ipvoid_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                honeypot_classification=intel_details.honeypot_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                web_of_trust_classification=intel_details.web_of_trust_classification or DEFAULT_INSIGHT_PLACEHOLDER,
                ipvoid_detections=intel_details.ipvoid_detections or DEFAULT_INSIGHT_PLACEHOLDER,
                itype=self.latest_indicator.itype or DEFAULT_INSIGHT_PLACEHOLDER,
                threat_type=self.latest_indicator.threat_type or DEFAULT_INSIGHT_PLACEHOLDER,
                source=self.latest_indicator.source or DEFAULT_INSIGHT_PLACEHOLDER,
                report_link=self.latest_indicator.report_link or DEFAULT_INSIGHT_PLACEHOLDER
            )

    def as_hash_insight(self):
        if self.active_indicators_count:
            return FILEHASH_INSIGHT_HTML_TEMPLATE.format(
                status=self.get_merged_attribute('status', self.active_indicators),
                severity=self.severity,
                severity_color=SEVERITIES_COLORS.get(self.severity),
                confidence=self.confidence,
                confidence_color=GREEN if self.confidence > 50 else ORANGE,
                itype=self.get_merged_attribute('itype', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                threat_type=self.get_merged_attribute('threat_type',
                                                      self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                source=self.get_merged_attribute('source', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                report_link=self.get_merged_attribute('report_link',
                                                      self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
            )

        else:
            return FILEHASH_INSIGHT_HTML_TEMPLATE.format(
                status=self.latest_indicator.status,
                severity=self.latest_indicator.severity,
                severity_color=SEVERITIES_COLORS.get(self.latest_indicator.severity),
                confidence=self.latest_indicator.confidence,
                confidence_color=GREEN if self.latest_indicator.confidence > 50 else ORANGE,
                itype=self.latest_indicator.itype or DEFAULT_INSIGHT_PLACEHOLDER,
                threat_type=self.latest_indicator.threat_type or DEFAULT_INSIGHT_PLACEHOLDER,
                source=self.latest_indicator.source or DEFAULT_INSIGHT_PLACEHOLDER,
                report_link=self.latest_indicator.report_link or DEFAULT_INSIGHT_PLACEHOLDER
            )

    def as_email_insight(self):
        if self.active_indicators_count:
            return EMAIL_INSIGHT_HTML_TEMPLATE.format(
                status=self.get_merged_attribute('status', self.active_indicators),
                severity=self.severity,
                severity_color=SEVERITIES_COLORS.get(self.severity),
                confidence=self.confidence,
                confidence_color=GREEN if self.confidence > 50 else ORANGE,
                itype=self.get_merged_attribute('itype', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                threat_type=self.get_merged_attribute('threat_type',
                                                      self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                source=self.get_merged_attribute('source', self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
                report_link=self.get_merged_attribute('report_link',
                                                      self.active_indicators) or DEFAULT_INSIGHT_PLACEHOLDER,
            )

        else:
            return EMAIL_INSIGHT_HTML_TEMPLATE.format(
                status=self.latest_indicator.status,
                severity=self.latest_indicator.severity,
                severity_color=SEVERITIES_COLORS.get(self.latest_indicator.severity),
                confidence=self.latest_indicator.confidence,
                confidence_color=GREEN if self.latest_indicator.confidence > 50 else ORANGE,
                itype=self.latest_indicator.itype or DEFAULT_INSIGHT_PLACEHOLDER,
                threat_type=self.latest_indicator.threat_type or DEFAULT_INSIGHT_PLACEHOLDER,
                source=self.latest_indicator.source or DEFAULT_INSIGHT_PLACEHOLDER,
                report_link=self.latest_indicator.report_link or DEFAULT_INSIGHT_PLACEHOLDER
            )


class AnalysisLink(object):
    """
    Threat Stream Analysis Link
    """
    def __init__(self, name, link):
        self.name = name
        self.link = link

    def as_csv(self):
        return {
            "Name": self.name,
            "Link": self.link
        }


class IntelDetails(object):
    """
    Threat Stream Intel Details
    """
    def __init__(self, raw_data, virus_total_classification=None, domain_tools_classification=None,
                 google_safe_browsing_classification=None, ipvoid_classification=None, honeypot_classification=None,
                 web_of_trust_classification=None, ipvoid_detections=None, **kwargs):
        self.raw_data = raw_data
        self.virus_total_classification = virus_total_classification
        self.domain_tools_classification = domain_tools_classification
        self.google_safe_browsing_classification = google_safe_browsing_classification
        self.ipvoid_classification = ipvoid_classification
        self.honeypot_classification = honeypot_classification
        self.web_of_trust_classification = web_of_trust_classification
        self.ipvoid_detections = ipvoid_detections


class JobStatus(object):
    """
    Threat Fuse job status of submitted observable
    """
    def __init__(self, raw_data, job_id=None, success=False, import_session_id=None):
        self.raw_data = raw_data,
        self.job_id = job_id
        self.success = success
        self.import_session_id = import_session_id


class JobDetails(object):
    """
    Threat FUse job details
    """

    def __init__(self, raw_data, numRejected, status, threat_type, **kwargs):
        self.raw_data = raw_data
        self.num_rejected = numRejected
        self.status = status
        self.job_id = id
        self.threat_type = threat_type

    @property
    def is_approved(self):
        return self.status == APPROVED_JOB_STATUS


class Association(object):
    """
    Threat Fuse Association
    """
    def __init__(self, raw_data, uuid=None, id=None, name=None, tags=None, modified_ts=None, created_ts=None,
                 published_ts=None, is_anonymous=None, aliases_objs=None, tlp=None, resource_uri=None, start_date=None,
                 end_date=None, status_display_name=None, s_type=None, parent_name=None, cvss2_score=None,
                 cvss3_score=None, primary_motivation=None, web_root=None, **kwargs):
        self.raw_data = raw_data
        self.uuid = uuid
        self.id = id
        self.name = name
        self.tags = tags or []  # list of values
        self.modified_ts = modified_ts  # UTC time
        self.created_ts = created_ts  # UTC time
        self.published_ts = published_ts
        self.is_anonymous = is_anonymous
        self.aliases = aliases_objs or []  # list of aliases data models
        self.primary_motivation = primary_motivation
        self.status_display_name = status_display_name
        self.parent_name = parent_name
        self.web_root = web_root
        self.start_date = start_date
        self.end_date = end_date
        self.signature_type = s_type
        self.tlp = tlp
        self.cvss2_score = cvss2_score
        self.cvss3_score = cvss3_score
        self.resource_uri = resource_uri

        if modified_ts:
            self.modified_ts_ms = convert_string_to_unix_time(self.modified_ts)
        else:
            self.modified_ts_ms = 1

    def as_json(self):
        return {
            'name': self.name,
            'id': self.id
        }

    def as_raw_json(self):
        return self.raw_data

    def as_csv(self, association_type):
        return {
            'ID': self.id,
            'Name': self.name,
            'Type (association name)': association_type,
            'Status': self.status_display_name if self.status_display_name else NOT_ASSIGNED
        }

    def as_insight(self, association_type):
        """
        Return insight data for association type
        :param association_type: {str} association type. Can be actor, campaign, tool, malware, signature...
        :return: insight data for association type
        """
        insight_func = getattr(self, f"as_{association_type}_insight", None)
        if insight_func:
            return insight_func()
        return self.as_general_insight(association_type)

    def as_actor_insight(self):
        return """Name: {}\nAliases: {}\nPrimary Motivation: {}\nMore Details: {}""".format(
            self.name,
            ' '.join([alias.name for alias in self.aliases]),
            self.primary_motivation if self.primary_motivation else NOT_ASSIGNED,
            as_html_link(f"{self.web_root}/actor/{self.id}")
        )

    def as_campaign_insight(self):
        return """Name: {}\nStatus: {}\nStart Date: {}\nEnd Date: {}\nMore Details: {}""".format(
            self.name,
            self.status_display_name,
            self.start_date,
            self.end_date,
            as_html_link(f"{self.web_root}/campaign/{self.id}")
        )

    def as_signature_insight(self):
        return """Name: {}\nSignature Type: {}\nCloned From: {}\n\nMore Details: {}""".format(
            self.name,
            self.signature_type,
            self.parent_name,
            as_html_link(f"{self.web_root}/signature/{self.id}")
        )

    def as_vulnerability_insight(self):
        return """Name: {}\nCVSS 2.0 Score: {}\nCVSS 3.0 Score: {}\n\nMore Details: {}""".format(
            self.name,
            self.cvss2_score,
            self.cvss3_score,
            as_html_link(f"{self.web_root}/vulnerability/{self.id}")
        )

    def as_incident_insight(self):
        return """Name: {}\nStatus: {}\nStart Date: {}\nEnd Date: {}\nMore Details: {}""".format(
            self.name,
            self.status_display_name,
            self.start_date,
            self.end_date,
            as_html_link(f"{self.web_root}/incident/{self.id}")
        )

    def as_malware_insight(self):
        return """Name: {}\nStatus: {}\nStart Date: {}\nEnd Date: {}\nMore Details: {}""".format(
            self.name,
            self.status_display_name,
            self.start_date,
            self.end_date,
            as_html_link(f"{self.web_root}/malware/{self.id}")
        )

    def as_tipreport_insight(self):
        return """Name: {}\nMore Details: {}""".format(
            self.name,
            as_html_link(f"{self.web_root}/tip/{self.id}")
        )

    def as_general_insight(self, association_type: str):
        return """Name: {}\nMore Details: {}""".format(
            self.name,
            as_html_link(f"{self.web_root}/{association_type}/{self.id}")
        )


class Alias(object):
    def __init__(self, alias_id, name, resource_uri):
        self.alias_id = alias_id
        self.name = name
        self.resource_uri = resource_uri


class BaseDetails():
    """
    All association details classes must inherit this class. (ActorDetails, CampaignDetails...) except IntelDetails/JobDetails
    because all association details are returned in the same action (Get Related Associations). Therefore
    1 CSV table and 1 insight is created for all of the different associations,
    """

    def as_json(self, **kwargs):
        return self.raw_data

    def as_insight(self, **kwargs):
        pass

    def as_csv(self, id=None, name=None, type=None, status=None):
        return {
            'ID': id if id else NOT_ASSIGNED,
            'Name': name if name else NOT_ASSIGNED,
            'Type': type if type else NOT_ASSIGNED,
            'Status': status if status else NOT_ASSIGNED
        }


class ThreatBulletinsDetails(BaseDetails):
    """
    Threat Fuse Threat Bulletins details
    """

    def __init__(self, raw_data, web_root=None, name=None, status_display_name=None, id=None, **kwargs):
        self.raw_data = raw_data
        self.id = id
        self.web_root = web_root
        self.status_display_name = status_display_name
        self.name = name

    def as_json(self):
        return self.raw_data

    def as_insight(self, number=None) -> str:
        return f"""
            {"<b>Threat Bulletins</b>" if number == 1 else ""}
            {f"{number}. " if number is not None else ""}{self.name if self.name else NOT_ASSIGNED}
            More Details: {as_html_link(f'{self.web_root}/tip/{self.id}')}
            """

    def as_csv(self):
        return super().as_csv(id=self.id, name=self.name, type="Threat Bulletins", status=self.status_display_name)


class ActorDetails(BaseDetails):
    """
    Threat Fuse actor details
    """
    def __init__(self, raw_data, id = None, primary_motivation=None, secondary_motivations=None,
                 sophistication_type_display_name=None, actor_motivations=None, aliases=None, types=None, name=None,
                 status_display_name=None, threat_actor_types=None, resource_level=None, victims=None, aliases_obj=None,
                 web_root=None, **kwargs):
        self.raw_data = raw_data
        self.web_root = web_root
        self.id = id
        self.name = name
        self.primary_motivation = primary_motivation
        self.secondary_motivations = secondary_motivations or []
        self.sophistication_type_display_name = sophistication_type_display_name
        self.actor_motivations = actor_motivations or []
        self.aliases = aliases or []
        self.aliases_obj = aliases_obj or []
        self.actor_types = types or []
        self.threat_actor_types = threat_actor_types or []
        self.resource_level = resource_level
        self.actor_victims = victims or []
        self.status_display_name = status_display_name

    def as_enrichment(self, prefix=ENRICHMENT_PREFIX):
        enrichment_data = {
            'primary_motivations': self.primary_motivation,
            'secondary_motivations': ', '.join(self.secondary_motivations) if self.secondary_motivations else "",
            'soph_type': self.sophistication_type_display_name,
            'motivations': ', '.join(
                [motivation.get("m_type", {}).get("display_name", "") for motivation in
                 self.actor_motivations]) if self.actor_motivations else "",
            'aliases': ', '.join([alias.name for alias in self.aliases_obj]) if self.aliases_obj else "",
            'operation_type': ', '.join(
                [type.get("a_type", {}).get("display_name", "") for type in
                 self.actor_types]) if self.actor_types else "",
            'report_link': f'{self.web_root}/actor/{self.id}'
        }
        return add_prefix_to_dict(dict_to_flat(enrichment_data), prefix)

    def as_json(self):
        return self.raw_data

    def as_insight(self, number=None):
        return f"""
            {"<b>Actor</b>" if number == 1 else ""}
            {f"{number}. " if number is not None else ""}{self.name if self.name else NOT_ASSIGNED}
            Aliases: {', '.join([alias.name for alias in self.aliases_obj]) if self.aliases_obj else NOT_ASSIGNED}
            Threat Actor Types: {', '.join(self.threat_actor_types) if self.threat_actor_types else NOT_ASSIGNED}
            Actor Level: {self.resource_level if self.resource_level else NOT_ASSIGNED}
            Primary Motivation: {self.primary_motivation if self.primary_motivation else NOT_ASSIGNED}
            Secondary Motivation: {', '.join(self.secondary_motivations) if self.secondary_motivations else NOT_ASSIGNED}
            Sophistication: {self.sophistication_type_display_name if self.sophistication_type_display_name else NOT_ASSIGNED}
            Operations Types: {', '.join([type.get("a_type", {}).get("display_name") for type in self.actor_types]) if self.actor_types else NOT_ASSIGNED}
            Victims: {', '.join([victim.get('name') for victim in self.actor_victims]) if self.actor_victims else NOT_ASSIGNED}
            More Details: {as_html_link(f'{self.web_root}/actor/{self.id}')}
            """

    def as_csv(self):
        return super().as_csv(id=self.id, name=self.name, type="Actor", status=self.status_display_name)


class AttackPatternDetails(BaseDetails):
    """
    Threat Fuse Attack Pattern details
    """

    def __init__(self, raw_data, web_root=None, name=None, status_display_name=None, id=None, **kwargs):
        self.raw_data = raw_data
        self.id = id
        self.web_root = web_root
        self.status_display_name = status_display_name
        self.name = name

    def as_json(self):
        return self.raw_data

    def as_insight(self, number=None) -> str:
        return f"""
            {"<b>Attack Pattern</b>" if number == 1 else ""}
            {f"{number}. " if number is not None else ""}{self.name if self.name else NOT_ASSIGNED}
            More Details: {as_html_link(f'{self.web_root}/attackpattern/{self.id}')}
            """

    def as_csv(self):
        return super().as_csv(id=self.id, name=self.name, type="Attack Pattern", status=self.status_display_name)


class CampaignDetails(BaseDetails):
    """
    Threat Fuse campaign details
    """

    def __init__(self, raw_data, id=None, aliases=None, aliases_obj=None, status_display_name=None, start_date=None,
                 name=None, end_date=None, victims=None, description=None, web_root=None, **kwargs):
        self.raw_data = raw_data
        self.web_root = web_root
        self.id = id
        self.aliases = aliases
        self.aliases_obj = aliases_obj or []
        self.status_display_name = status_display_name
        self.start_date = start_date
        self.end_date = end_date
        self.name = name
        self.victims = victims or []

    def as_enrichment(self, prefix=ENRICHMENT_PREFIX):
        enrichment_data = {
            'id': self.id,
            'aliases': ', '.join([alias.name for alias in self.aliases_obj]) if self.aliases_obj else "",
            'status': self.status_display_name if self.status_display_name else "",
            'start_date': self.start_date if self.start_date else "",
            'end_data': self.end_date if self.end_date else "",
            'victims': ', '.join([victim.get('name') for victim in self.victims]) if self.victims else "",
            'report_link': f'{self.web_root}/campaign/{self.id}'
        }
        return add_prefix_to_dict(dict_to_flat(enrichment_data), prefix)

    def as_json(self):
        return self.raw_data

    def as_insight(self, number=None) -> str:
        return f"""
            {"<b>Campaign</b>" if number == 1 else " "}
            {f"{number}. " if number is not None else ""}{self.name}
            Status: {self.status_display_name if self.status_display_name else NOT_ASSIGNED}
            Aliases: {', '.join([alias.name for alias in self.aliases_obj]) if self.aliases_obj else NOT_ASSIGNED}
            Start Date: {self.start_date if self.start_date else NOT_ASSIGNED}
            End Date: {self.end_date if self.end_date else NOT_ASSIGNED}
            Victims: {', '.join([victim.get('name') for victim in self.victims]) if self.victims else NOT_ASSIGNED}
            More Details: {as_html_link(f'{self.web_root}/campaign/{self.id}')}
            """

    def as_csv(self):
        return super().as_csv(id=self.id, name=self.name, type="Campaign", status=self.status_display_name)


class CourseOfActionDetails(BaseDetails):
    """
    Threat Fuse Course Of Action details
    """

    def __init__(self, raw_data, web_root=None, name=None, status_display_name=None, id=None, **kwargs):
        self.raw_data = raw_data
        self.id = id
        self.web_root = web_root
        self.status_display_name = status_display_name
        self.name = name

    def as_json(self):
        return self.raw_data

    def as_insight(self, number=None) -> str:
        return f"""
            {"<b>Course of Action</b>" if number == 1 else ""}
            {f"{number}. " if number is not None else ""}{self.name if self.name else NOT_ASSIGNED}
            More Details: {as_html_link(f'{self.web_root}/courseofaction/{self.id}')}
            """

    def as_csv(self):
        return super().as_csv(id=self.id, name=self.name, type="Course Of Action", status=self.status_display_name)


class IdentityDetails(BaseDetails):
        """
        Threat Fuse Identity details
        """

        def __init__(self, raw_data, web_root=None, name=None, status_display_name=None, id=None, **kwargs):
            self.raw_data = raw_data
            self.id = id
            self.web_root = web_root
            self.status_display_name = status_display_name
            self.name = name

        def as_json(self):
            return self.raw_data

        def as_insight(self, number=None) -> str:
            return f"""
                {"<b>Identity</b>" if number == 1 else ""}
                {f"{number}. " if number is not None else ""}{self.name if self.name else NOT_ASSIGNED}
                More Details: {as_html_link(f'{self.web_root}/identity/{self.id}')}
                """

        def as_csv(self):
            return super().as_csv(id=self.id, name=self.name, type="Identity", status=self.status_display_name)


class IncidentDetails(BaseDetails):
    """
    Threat Fuse Incident details
    """

    def __init__(self, raw_data, web_root=None, name=None, status_display_name=None, start_date=None, end_date=None,
                 id=None,
                 **kwargs):
        self.raw_data = raw_data
        self.id = id
        self.web_root = web_root
        self.status_display_name = status_display_name
        self.name = name
        self.start_date = start_date
        self.end_date = end_date

    def as_json(self):
        return self.raw_data

    def as_insight(self, number=None) -> str:
        return f"""
            {"<b>Incident</b>" if number == 1 else ""}
            {f"{number}. " if number is not None else ""}{self.name if self.name else NOT_ASSIGNED}
            Status: {self.status_display_name if self.status_display_name else NOT_ASSIGNED}
            Start Date: {self.start_date if self.start_date else NOT_ASSIGNED}
            End Date: {self.end_date if self.end_date else NOT_ASSIGNED} 
            More Details: {as_html_link(f'{self.web_root}/incident/{self.id}')}
            """

    def as_csv(self):
        return super().as_csv(id=self.id, name=self.name, type="Incident", status=self.status_display_name)


class InfrastructureDetails(BaseDetails):
    """
    Threat Fuse Infrastructure details
    """

    def __init__(self, raw_data, web_root=None, name=None, status_display_name=None, id=None, **kwargs):
        self.raw_data = raw_data
        self.id = id
        self.web_root = web_root
        self.status_display_name = status_display_name
        self.name = name

    def as_json(self):
        return self.raw_data

    def as_insight(self, number=None) -> str:
        return f"""
            {"<b>Infrastructure</b>" if number == 1 else ""}
            {f"{number}. " if number is not None else ""}{self.name if self.name else NOT_ASSIGNED}
            More Details: {as_html_link(f'{self.web_root}/infrastructure/{self.id}')}
            """

    def as_csv(self):
        return super().as_csv(id=self.id, name=self.name, type="Infrastructure", status=self.status_display_name)


class IntrusionSetDetails(BaseDetails):
    """
    Threat Fuse Intrusion Set details
    """

    def __init__(self, raw_data, web_root=None, name=None, status_display_name=None, id=None, **kwargs):
        self.raw_data = raw_data
        self.id = id
        self.web_root = web_root
        self.status_display_name = status_display_name
        self.name = name

    def as_json(self):
        return self.raw_data

    def as_insight(self, number=None) -> str:
        return f"""
            {"<b>Intrusion Set</b>" if number == 1 else ""}
            {f"{number}. " if number is not None else ""}{self.name if self.name else NOT_ASSIGNED}
            More Details: {as_html_link(f'{self.web_root}/intrusionset/{self.id}')}
            """

    def as_csv(self):
        return super().as_csv(id=self.id, name=self.name, type="Intrusion Set", status=self.status_display_name)


class MalwareDetails(BaseDetails):
    """
    Threat Fuse Malware details
    """

    def __init__(self, raw_data, web_root=None, name=None, status_display_name=None, first_seen=None, last_seen=None,
                 id=None, **kwargs):
        self.raw_data = raw_data
        self.id = id
        self.web_root = web_root
        self.status_display_name = status_display_name
        self.name = name
        self.first_seen = first_seen
        self.last_seen = last_seen

    def as_json(self):
        return self.raw_data

    def as_insight(self, number=None) -> str:
        return f"""
            {"<b>Malware</b>" if number == 1 else ""}
            {f"{number}. " if number is not None else ""}{self.name if self.name else NOT_ASSIGNED}
            Status: {self.status_display_name if self.status_display_name else NOT_ASSIGNED}
            First Seen: {self.first_seen if self.first_seen else NOT_ASSIGNED}
            Last Seen: {self.last_seen if self.last_seen else NOT_ASSIGNED}
            More Details: {as_html_link(f'{self.web_root}/malware/{self.id}')}
            """

    def as_csv(self):
        return super().as_csv(id=self.id, name=self.name, type="Malware", status=self.status_display_name)


class SignatureDetails(BaseDetails):
    """
    Threat Fuse signature details
    """

    def __init__(self, raw_data, id=None, parent_display_name=None, signature_type_name=None, aliases=None,
                 aliases_obj=None, victims=None, start_date=None, end_date=None, web_root=None,
                 status_display_name=None, name=None, **kwargs):
        self.raw_data = raw_data
        self.web_root = web_root
        self.id = id
        self.name = name
        self.signature_type_name = signature_type_name
        self.parent_display_name = parent_display_name
        self.status_display_name = status_display_name
        self.aliases = aliases
        self.aliases_obj = aliases_obj or []
        self.start_date = start_date
        self.end_date = end_date
        self.victims = victims or []

    def as_enrichment(self, prefix=ENRICHMENT_PREFIX):
        enrichment_data = {
            'id': self.id,
            'cloned_from': self.parent_display_name if self.parent_display_name else "",
            'signature_type': self.signature_type_name if self.signature_type_name else "",
            'report_link': f'{self.web_root}/signature/{self.id}'
        }
        return add_prefix_to_dict(dict_to_flat(enrichment_data), prefix)

    def as_json(self):
        return self.raw_data

    def as_insight(self, number=None) -> str:
        return f"""
            {"<b>Signature</b>" if number == 1 else ""}
            {f"{number}. " if number is not None else ""}{self.name if self.name else NOT_ASSIGNED}
            Aliases: {', '.join([alias.name for alias in self.aliases_obj]) if self.aliases_obj else NOT_ASSIGNED}
            Cloned From: {self.parent_display_name if self.parent_display_name else NOT_ASSIGNED}
            Signature Type: {self.signature_type_name if self.signature_type_name else NOT_ASSIGNED}
            Status: {self.status_display_name if self.status_display_name else NOT_ASSIGNED}
            Start Date: {self.start_date if self.start_date else NOT_ASSIGNED}
            End Date: {self.end_date if self.end_date else NOT_ASSIGNED}
            Victims: {', '.join([victim.get('name') for victim in self.victims]) if self.victims else NOT_ASSIGNED}
            More Details: {as_html_link(f'{self.web_root}/signature/{self.id}')}
            """

    def as_csv(self):
        return super().as_csv(id=self.id, name=self.name, type="Signature", status=self.status_display_name)


class ToolDetails(BaseDetails):
    """
    Threat Fuse Tool details
    """

    def __init__(self, raw_data, web_root=None, name=None, status_display_name=None, id=None, **kwargs):
        self.raw_data = raw_data
        self.id = id
        self.web_root = web_root
        self.status_display_name = status_display_name
        self.name = name

    def as_json(self):
        return self.raw_data

    def as_insight(self, number=None) -> str:
        return f"""
            {"<b>Tool</b>" if number == 1 else ""}
            {f"{number}. " if number is not None else ""}{self.name if self.name else NOT_ASSIGNED}
            More Details: {as_html_link(f'{self.web_root}/tool/{self.id}')}
            """

    def as_csv(self):
        return super().as_csv(id=self.id, name=self.name, type="Tool", status=self.status_display_name)

class TTPDetails(BaseDetails):
    """
    Threat Fuse TTP details
    """

    def __init__(self, raw_data, web_root=None, name=None, status_display_name=None, id=None, **kwargs):
        self.raw_data = raw_data
        self.id = id
        self.web_root = web_root
        self.status_display_name = status_display_name
        self.name = name

    def as_json(self):
        return self.raw_data

    def as_insight(self, number=None) -> str:
        return f"""
            {"<b>TTP</b>" if number == 1 else ""}
            {f"{number}. " if number is not None else ""}{self.name if self.name else NOT_ASSIGNED}
            More Details: {as_html_link(f'{self.web_root}/ttp/{self.id}')}
            """

    def as_csv(self):
        return super().as_csv(id=self.id, name=self.name, type="TTP", status=self.status_display_name)

class Vulnerability(BaseDetails):
    """
    Threat Fuse Vulnerability details
    """

    def __init__(self, raw_data, id=None, cvss2_score=None, cvss3_score=None, web_root=None, name=None,
                 status_display_name=None, **kwargs):
        self.raw_data = raw_data
        self.web_root = web_root
        self.id = id
        self.cvss2_score = cvss2_score
        self.cvss3_score = cvss3_score
        self.name = name
        self.status_display_name = status_display_name

    @property
    def report_link(self) -> str:
        return f'{self.web_root}/vulnerability/{self.id}'

    def as_enrichment(self, prefix=ENRICHMENT_PREFIX):
        enrichment_data = {
            'id': self.id,
            'cvss2_score': self.cvss2_score,
            'cvss3_score': self.cvss3_score,
            'report_link': self.report_link
        }
        return add_prefix_to_dict(dict_to_flat(enrichment_data), prefix)

    def as_insight(self, number=None) -> str:
        return f"""
            {"<b>Vulnerability</b>" if number == 1 else ""}
            {f"{number}. " if number is not None else ""}{self.name if self.name else NOT_ASSIGNED}
            CVSS 2.0 Score: {self.cvss2_score if self.cvss2_score is not None else NOT_ASSIGNED}
            CVSS 3.0 Score: {self.cvss3_score if self.cvss3_score is not None else NOT_ASSIGNED}
            More Details: {as_html_link(self.report_link)}
            """

    def as_csv(self):
        return super().as_csv(id=self.id, name=self.name, type="Vulnerability", status=self.status_display_name)
