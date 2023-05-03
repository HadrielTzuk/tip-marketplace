from datamodels import *
from constants import CASE_WALL_LINK


class VirusTotalParser(object):
    def build_results(self, raw_data, method):
        return [getattr(self, method)(item_json) for item_json in raw_data.get('data', [])]

    def extract_data_from_raw_data(self, raw_data):
        return raw_data.get("data", {})

    def build_last_analysis_results(self, raw_data):
        return {engine: self.build_engine_data(engine_data_json) for engine, engine_data_json in
                raw_data.get('attributes', {}).get('last_analysis_results', {}).items()}

    def build_last_dns_results(self, raw_data):
        return [self.build_dns_data(dns_data_json) for dns_data_json in
                raw_data.get('attributes', {}).get('last_dns_records', [])]

    def build_ip_object(self, raw_data, entity_type, entity):
        raw_data = self.extract_data_from_raw_data(raw_data)
        return IP(
            raw_data=raw_data,
            entity_id=raw_data.get('id', ''),
            as_owner=raw_data.get('attributes', {}).get('as_owner', ''),
            asn=raw_data.get('attributes', {}).get('asn', ''),
            continent=raw_data.get('attributes', {}).get('continent', ''),
            country=raw_data.get('attributes', {}).get('country', ''),
            last_analysis_stats=raw_data.get('attributes', {}).get('last_analysis_stats', {}),
            last_analysis_results=self.build_last_analysis_results(raw_data=raw_data),
            harmless=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('harmless', 0),
            malicious=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0),
            suspicious=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('suspicious', 0),
            undetected=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('undetected', 0),
            not_after=raw_data.get('attributes', {}).get('last_https_certificate', {}).get('validity', {}).get(
                'not_after', ''),
            not_before=raw_data.get('attributes', {}).get('last_https_certificate', {}).get('validity', {}).get(
                'not_before', ''),
            reputation=raw_data.get('attributes', {}).get('reputation', 0),
            tags=raw_data.get('attributes', {}).get('tags', []),
            total_votes_harmless=raw_data.get('attributes', {}).get('total_votes', {}).get('harmless', 0),
            total_votes_malicious=raw_data.get('attributes', {}).get('total_votes', {}).get('malicious', 0),
            report_link=CASE_WALL_LINK.format(entity_type=entity_type, entity=entity),
        )

    def build_url_object(self, raw_data, entity_type, entity):
        raw_data = self.extract_data_from_raw_data(raw_data)
        return URL(
            raw_data=raw_data,
            entity_id=raw_data.get('id', ''),
            title=raw_data.get('attributes', {}).get('title', ''),
            categories=raw_data.get('attributes', {}).get('categories', {}),
            last_http_response_code=raw_data.get('attributes', {}).get('last_http_response_code', ''),
            last_http_response_content_length=raw_data.get('attributes', {}).get('last_http_response_content_length',
                                                                                 ''),
            threat_names=raw_data.get('attributes', {}).get('threat_names', ''),
            last_analysis_stats=raw_data.get('attributes', {}).get('last_analysis_stats', {}),
            last_analysis_results=self.build_last_analysis_results(raw_data=raw_data),
            harmless=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('harmless', 0),
            malicious=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0),
            suspicious=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('suspicious', 0),
            undetected=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('undetected', 0),
            reputation=raw_data.get('attributes', {}).get('reputation', 0),
            tags=raw_data.get('attributes', {}).get('tags', []),
            total_votes_harmless=raw_data.get('attributes', {}).get('total_votes', {}).get('harmless', 0),
            total_votes_malicious=raw_data.get('attributes', {}).get('total_votes', {}).get('malicious', 0),
            report_link=CASE_WALL_LINK.format(entity_type=entity_type, entity=entity),
            last_analysis_date=raw_data.get('attributes', {}).get('last_analysis_date', 0)
        )

    def build_engine_data(self, raw_data):
        return EngineData(
            raw_data=raw_data,
            category=raw_data.get('category'),
            engine_name=raw_data.get('engine_name'),
            method=raw_data.get('method'),
            result=raw_data.get('result'),
        )

    def build_dns_data(self, raw_data):
        return DnsData(
            raw_data=raw_data,
            dns_type=raw_data.get('type'),
            ttl=raw_data.get('ttl'),
            value=raw_data.get('value')
        )

    def build_hash_object(self, raw_data, entity_type, entity):
        raw_data = self.extract_data_from_raw_data(raw_data)
        return Hash(
            raw_data=raw_data,
            entity_id=raw_data.get('id', ''),
            magic=raw_data.get('attributes', {}).get('magic', ''),
            md5=raw_data.get('attributes', {}).get('md5', ''),
            sha1=raw_data.get('attributes', {}).get('sha1', ''),
            sha256=raw_data.get('attributes', {}).get('sha256', ''),
            ssdeep=raw_data.get('attributes', {}).get('ssdeep', ''),
            tlsh=raw_data.get('attributes', {}).get('tlsh', ''),
            vhash=raw_data.get('attributes', {}).get('vhash', ''),
            meaningful_name=raw_data.get('attributes', {}).get('meaningful_name', ''),
            names=raw_data.get('attributes', {}).get('names', []),
            last_analysis_results=self.build_last_analysis_results(raw_data=raw_data),
            harmless=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('harmless', 0),
            malicious=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0),
            suspicious=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('suspicious', 0),
            undetected=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('undetected', 0),
            reputation=raw_data.get('attributes', {}).get('reputation', 0),
            tags=raw_data.get('attributes', {}).get('tags', []),
            total_votes_harmless=raw_data.get('attributes', {}).get('total_votes', {}).get('harmless', 0),
            total_votes_malicious=raw_data.get('attributes', {}).get('total_votes', {}).get('malicious', 0),
            report_link=CASE_WALL_LINK.format(entity_type=entity_type, entity=entity),
            exiftool=raw_data.get('attributes', {}).get('exiftool', {}),
            file_type=raw_data.get('attributes', {}).get('exiftool', {}).get('FileType', ''),
            file_description=raw_data.get('attributes', {}).get('exiftool', {}).get('FileDescription', ''),
            original_file_name=raw_data.get('attributes', {}).get('exiftool', {}).get('OriginalFileName', ''),
            last_analysis_date=raw_data.get('attributes', {}).get('last_analysis_date', 0)
        )

    def get_comment(self, raw_data):
        return Comment(
            raw_data=raw_data,
            comment_id=raw_data.get('id', ''),
            date=raw_data.get('attributes', {}).get('date', ''),
            comment=raw_data.get('attributes', {}).get('text', ''),
            abuse_votes=raw_data.get('attributes', {}).get('votes', {}).get('abuse', 0),
            positive_votes=raw_data.get('attributes', {}).get('votes', {}).get('positive', 0),
            negative_votes=raw_data.get('attributes', {}).get('votes', {}).get('negative', 0),
        )

    def get_analysis_status(self, raw_data):
        return raw_data.get('data', {}).get('attributes', {}).get('status')

    def get_analysis_id(self, raw_data):
        return raw_data.get('data', {}).get('id')

    def get_file_hash_from_analysis(self, raw_data):
        return raw_data.get('meta', {}).get('file_info', {}).get('sha256', '')

    def get_next_page_url(self, raw_data):
        return raw_data.get('links', {}).get('next')

    def build_analysis_object(self, raw_data):
        raw_data = self.extract_data_from_raw_data(raw_data)
        return SigmaAnalysis(
            raw_data=raw_data,
            rule_matches=self.build_rule_matches(raw_data=raw_data)
        )

    def build_rule_matches(self, raw_data):
        return [self.build_rule_match(rule_match) for rule_match in
                raw_data.get('attributes', {}).get('rule_matches', [])]

    def build_rule_match(self, item):
        return RuleMatch(
            raw_data=item,
            id=item.get('rule_id', ''),
            level=item.get('rule_level', ''),
            source=item.get('rule_source', ''),
            title=item.get('rule_title', ''),
            description=item.get('rule_description', ''),
            match_context=item.get('match_context', '')
        )

    def get_url_relation(self, raw_data):
        return Relation(
            raw_data=raw_data,
            url=raw_data.get('context_attributes', {}).get('url', '')
        )


    def build_domain_object(self, raw_data, entity_type, entity):
        raw_data = self.extract_data_from_raw_data(raw_data)
        return Domain(
            raw_data=raw_data,
            entity_id=raw_data.get('id', ''),
            tags=raw_data.get('attributes', {}).get('tags', []),
            categories=raw_data.get('attributes', {}).get('categories', {}),
            last_dns_records=self.build_last_dns_results(raw_data=raw_data),
            last_analysis_stats=raw_data.get('attributes', {}).get('last_analysis_stats', {}),
            last_analysis_results=self.build_last_analysis_results(raw_data=raw_data),
            harmless=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('harmless', 0),
            malicious=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0),
            suspicious=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('suspicious', 0),
            undetected=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('undetected', 0),
            reputation=raw_data.get('attributes', {}).get('reputation', 0),
            total_votes_harmless=raw_data.get('attributes', {}).get('total_votes', {}).get('harmless', 0),
            total_votes_malicious=raw_data.get('attributes', {}).get('total_votes', {}).get('malicious', 0),
            whois=raw_data.get('attributes', {}).get('whois', ''),
            report_link=CASE_WALL_LINK.format(entity_type=entity_type, entity=entity)
        )

    def get_hash_relation(self, raw_data):
        return RelatedHash(
            raw_data=raw_data,
            file_hash=raw_data.get('id', '')
        )

    def get_ip_relation(self, raw_data):
        return RelatedIp(
            raw_data=raw_data,
            ip=raw_data.get('id', '')
        )

    def get_graph(self, raw_data):
        return Graph(
            raw_data=raw_data,
            attributes=raw_data.get('attributes', {}),
            graph_id=raw_data.get('id', ''),
            links=self.build_link_results(raw_data=raw_data)
        )

    def get_domain_relation(self, raw_data):
        return RelatedDomain(
            raw_data=raw_data,
            domain=raw_data.get('id')
        )

    def build_graph_object(self, raw_data, limit_for_links=None):
        raw_data = self.extract_data_from_raw_data(raw_data=raw_data)
        # Max Links To Return
        # Result filtering is done on our side.
        if limit_for_links:
            links = raw_data.get('attributes', {}).get('links', [])[:limit_for_links]
            if links:
                raw_data['attributes']['links'] = links

        return self.get_graph(raw_data=raw_data)

    def build_link_results(self, raw_data):
        return [self.build_link_data(link_data) for link_data in raw_data.get('attributes', {}).get('links', [])]

    def build_link_data(self, raw_data):
        return Link(
            raw_data=raw_data,
            connection_type=raw_data.get('connection_type'),
            source=raw_data.get('source'),
            target=raw_data.get('target')
        )

    def get_upload_url(self, raw_data):
        return self.extract_data_from_raw_data(raw_data)

    def build_ioc_object(self, raw_data):
        return Ioc(
            raw_data=raw_data,
            last_analysis_results=self.build_last_analysis_results(raw_data=raw_data)
        )

    @staticmethod
    def build_sandbox_object(raw_data):
        return Sandbox(
            raw_data=raw_data
        )

    def build_notification_object(self, raw_data):
        return Notification(
            raw_data=raw_data,
            id=raw_data.get('context_attributes', {}).get('notification_id', ''),
            meaningful_name=raw_data.get('attributes', {}).get('meaningful_name', ''),
            rule_name=raw_data.get('context_attributes', {}).get('rule_name', ''),
            notification_date=raw_data.get('context_attributes', {}).get('notification_date', ''),
            last_analysis_stats=raw_data.get('attributes', {}).get('last_analysis_stats', {}),
            last_analysis_results=self.build_last_analysis_results(raw_data=raw_data),
            malicious=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0),
            suspicious=raw_data.get('attributes', {}).get('last_analysis_stats', {}).get('suspicious', 0)
        )
