from datamodels import (
    IOC,
    IOCDetail,
    Asset,
    Event,
    Alert,
    Detection,
    ChronicleCase,
    ChronicleAlert,
    CaseMetadata,
    AlertMetadata,
    MultipartResponsePart,
    UdmQueryEvent
)
from copy import deepcopy
import regex
from consts import JSON_REGEX_PATTERN


class GoogleChronicleParser(object):
    """
    Google Chronicle Transformation Layer.
    """
    @staticmethod
    def build_siemplify_ioc_obj(ioc_data, fallback_severity=None):
        raw_data = deepcopy(ioc_data)
        sources = [GoogleChronicleParser.build_siemplify_ioc_source_obj(source) for source in ioc_data.pop("sources", [])]

        return IOC(
            raw_data=raw_data,
            domain_name=raw_data.get("artifact", {}).get("domainName"),
            sources=sources,
            fallback_severity=fallback_severity,
            **ioc_data
        )

    @staticmethod
    def build_siemplify_ioc_source_obj(source_data):
        return IOC.Source(
            raw_data=source_data,
            intRawConfidenceScore=source_data.get('confidenceScore', {}).get('intRawConfidenceScore'),
            normalizedConfidenceScore=source_data.get('confidenceScore', {}).get('normalizedConfidenceScore'),
            **source_data
        )

    @staticmethod
    def build_siemplify_ioc_detail_obj(ioc_detail_data):
        raw_data = deepcopy(ioc_detail_data)
        sources = [GoogleChronicleParser.build_siemplify_ioc_detail_source_obj(source) for source in
                   ioc_detail_data.pop("sources", [])]

        return IOCDetail(
            raw_data=raw_data,
            sources=sources,
            **ioc_detail_data
        )

    @staticmethod
    def build_siemplify_ioc_detail_source_obj(source_data):
        raw_data = deepcopy(source_data)
        addresses = GoogleChronicleParser.build_siemplify_ioc_detail_source_addresses_obj(source_data.pop("addresses", []))

        return IOCDetail.Source(
            raw_data=raw_data,
            strRawConfidenceScore=source_data.get('confidenceScore', {}).get('strRawConfidenceScore'),
            addresses=addresses,
            **source_data
        )

    @staticmethod
    def build_siemplify_ioc_detail_source_addresses_obj(addresses):
        return [IOCDetail.Source.Address(raw_data=address, **address) for address in addresses]

    @staticmethod
    def build_siemplify_asset_obj(asset_data):
        return Asset(
            asset_data,
            hostname=asset_data.get("asset", {}).get("hostname"),
            ip_address=asset_data.get("asset", {}).get("assetIpAddress"),
            first_seen_artifact_time=asset_data.get("firstSeenArtifactInfo", {}).get("seenTime"),
            last_seen_artifact_time=asset_data.get("lastSeenArtifactInfo", {}).get("seenTime"),
            **asset_data
        )

    @staticmethod
    def build_siemplify_alert_obj(alert_data, alert_type=None, fallback_severity=None):
        raw_data = deepcopy(alert_data)
        alert_infos = [GoogleChronicleParser.build_siemplify_alert_info_obj(alert_info, alert_type, fallback_severity)
                       for alert_info in alert_data.pop("alertInfos", [])]

        return Alert(
            raw_data,
            hostname=alert_data.get("asset", {}).get("hostname"),
            ip_address=alert_data.get("asset", {}).get("assetIpAddress"),
            mac=alert_data.get("asset", {}).get("mac"),
            alert_infos=alert_infos,
            **alert_data
        )

    @staticmethod
    def build_siemplify_alert_info_obj(alert_info_data, alert_type=None, fallback_severity=None):
        return Alert.AlertInfo(
            raw_data=alert_info_data,
            alert_type=alert_type,
            fallback_severity=fallback_severity,
            **alert_info_data
        )

    @staticmethod
    def build_siemplify_event_obj(event_data):
        return Event(
            raw_data=event_data,
            event_type=event_data.get("metadata", {}).get("eventType"),
            product_name=event_data.get("metadata", {}).get("productName"),
            timestamp=event_data.get("metadata", {}).get("eventTimestamp")
        )

    @staticmethod
    def build_detection(raw_data, fallback_severity=None):
        detections = raw_data.get('detection', [{}])
        first_detection = detections[0]

        return Detection(
            raw_data=raw_data,
            identifier=raw_data.get('id'),
            rule_id=first_detection.get('ruleId'),
            alert_state=first_detection.get('alertState'),
            name=first_detection.get('ruleName'),
            created_time=raw_data.get('createdTime'),
            start_time=raw_data.get('timeWindow', {}).get('startTime'),
            end_time=raw_data.get('timeWindow', {}).get('endTime'),
            detections=detections,
            collection_elements=raw_data.get('collectionElements', []),
            rule_type=raw_data.get('type', ''),
            url_back_to_product=first_detection.get('urlBackToProduct'),
            fallback_severity=fallback_severity
        )

    @staticmethod
    def build_chronicle_case_obj(case_data):
        return ChronicleCase(
            raw_data=case_data,
            id=str(case_data.get('case_id')),
            external_id=case_data.get('external_case_id', "") or "",
            priority=case_data.get('priority'),
            status=case_data.get('status'),
            environment=case_data.get('environment'),
            stage=case_data.get('stage'),
            has_failed=False,
            tracking_time=case_data.get('tracking_time'),
            display_name=case_data.get('title')
        )

    @staticmethod
    def build_chronicle_alert_obj(alert_data):
        return ChronicleAlert(
            raw_data=alert_data,
            id=alert_data.get('alert_id'),
            ticket_id=alert_data.get('ticket_id'),
            creation_time=alert_data.get('creation_time'),
            priority=alert_data.get('priority'),
            status=alert_data.get('status'),
            environment=alert_data.get('environment'),
            comment=alert_data.get('close_comment'),
            has_failed=False,
            tracking_time=alert_data.get('tracking_time'),
            reason=alert_data.get('close_reason'),
            root_cause=alert_data.get('close_root_cause'),
            case_id=alert_data.get('case_id'),
            group_id=alert_data.get('alert_group_id'),
            usefulness=alert_data.get('close_usefulness')
        )

    @staticmethod
    def build_case_metadata_obj(raw_data):
        return CaseMetadata(
            raw_data=raw_data,
            id=raw_data.get('case_id'),
            tracking_time=raw_data.get('tracking_time')
        )

    @staticmethod
    def build_alert_metadata_obj(raw_data):
        return AlertMetadata(
            raw_data=raw_data,
            group_id=raw_data.get('alert_group_id'),
            tracking_time=raw_data.get('tracking_time')
        )

    @staticmethod
    def parse_multipart_response(response):
        """
        :param response: requests.Response object
        return a list of requests.Response-like objects
        """

        def build_part_obj(raw_part):
            body_pattern = regex.compile(JSON_REGEX_PATTERN)
            status_code_pattern = regex.compile(r'HTTP/\d\.\d\s(\d+)')
            header_pattern = regex.compile(r'.+:\s[\w\- //]+')

            body = body_pattern.findall(raw_part)[0]
            status_code = status_code_pattern.findall(raw_part)[0]

            raw_headers = header_pattern.findall(raw_part[:raw_part.find(body)])
            raw_headers = [header.split(":") for header in raw_headers]
            headers = {header[0].strip(): header[1].strip() for header in raw_headers}

            return MultipartResponsePart(body=body.encode("utf-8"), headers=headers, status_code=int(status_code))

        boundary = f'--{response.headers.get("Content-Type").split("boundary=")[-1]}'
        raw_parts = response.text.split(boundary)[1:-1]
        return [build_part_obj(raw_part) for raw_part in raw_parts]

    def build_udm_query_event_objects(self, raw_data):
        return [self.build_udm_query_event_object(item)
                for item in raw_data.get("events", [])]

    @staticmethod
    def build_udm_query_event_object(raw_data):
        return UdmQueryEvent(
            raw_data=raw_data
        )
