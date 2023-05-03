from TIPCommon import add_prefix_to_dict, dict_to_flat
from constants import DATA_ENRICHMENT_PREFIX, IGNORED_CATEGORIES, IOC_LINK_STRUCTURE, IOC_LINK_ITEMS_MAPPING, \
    DEVICE_VENDOR, DEVICE_PRODUCT, FALLBACK_NAME
from UtilsManager import convert_list_to_comma_string
from SiemplifyDataModel import EntityTypes


class BaseModel(object):
    """
    Base model for inheritance
    """

    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data


class EngineData(BaseModel):
    def __init__(self, raw_data, category=None, engine_name=None, method=None, result=None):
        super(EngineData, self).__init__(raw_data)
        self.category = category
        self.engine_name = engine_name
        self.method = method
        self.result = result


class DnsData(BaseModel):
    def __init__(self, raw_data, dns_type=None, ttl=None, value=None):
        super(DnsData, self).__init__(raw_data)
        self.type = dns_type
        self.ttl = ttl
        self.value = value


class VirusTotalEntity(BaseModel):
    def __init__(self, raw_data, last_analysis_results, malicious, suspicious):
        super(VirusTotalEntity, self).__init__(raw_data)
        self.last_analysis_results = last_analysis_results
        self.malicious = malicious
        self.suspicious = suspicious
        self.supported_engines = []
        self.invalid_engines = []

    def set_supported_engines(self, engines):
        available_engines = self.last_analysis_results.keys()
        for engine in engines:
            if engine in available_engines:
                self.supported_engines.append(engine)
            else:
                self.invalid_engines.append(engine)

    def get_enrichment_data(self):
        raise NotImplementedError

    def to_enrichment_data(self, widget_link=None):
        clean_enrichment_data = {k: v for k, v in self.get_enrichment_data().items() if v}

        if widget_link:
            clean_enrichment_data["widget_link"] = widget_link

        return add_prefix_to_dict(clean_enrichment_data, DATA_ENRICHMENT_PREFIX)

    def to_table(self):
        engine_csvs = []
        expected_engines = {k: v for k, v in self.last_analysis_results.items() if k in self.supported_engines} \
            if self.supported_engines else self.last_analysis_results

        for key, engine in expected_engines.items():
            engine_csvs.append({
                "Name": key,
                "Category": engine.category,
                "Method": engine.method,
                "Result": engine.result,
            })

        return engine_csvs

    def to_json(self, comments=None, widget_link=None, widget_html=None):
        if comments:
            self.raw_data['comments'] = [comment.to_json() for comment in comments]
        self.raw_data['widget_url'] = widget_link
        # self.raw_data['widget_html'] = widget_html
        return self.raw_data

    @property
    def threshold(self):
        if not self.supported_engines:
            return self.malicious + self.suspicious

        threshold, threshold_keys = 0, ['malicious', 'suspicious']

        for engine in self.last_analysis_results.keys():
            if engine not in self.supported_engines:
                continue

            if self.last_analysis_results.get(engine, EngineData({})).category in threshold_keys:
                threshold += 1

        return threshold

    @property
    def percentage_threshold(self):
        engines_with_result = [engine for engine, data in self.last_analysis_results.items() if data.category not in
                               IGNORED_CATEGORIES]
        if not self.supported_engines:
            return int((self.malicious + self.suspicious) / len(engines_with_result) * 100) if engines_with_result else 0

        threshold, threshold_keys = 0, ['malicious', 'suspicious']

        for engine in self.last_analysis_results.keys():
            if engine not in self.supported_engines:
                continue

            if self.last_analysis_results.get(engine, EngineData({})).category in threshold_keys:
                threshold += 1

        return int(threshold / len([engine for engine in self.supported_engines if engine in engines_with_result]) *
                   100) if engines_with_result else 0


class IP(VirusTotalEntity):
    def __init__(self, raw_data, entity_id, as_owner, asn, continent, country, last_analysis_stats,
                 last_analysis_results, harmless, malicious, suspicious, undetected, not_after, not_before, reputation,
                 tags, total_votes_harmless, total_votes_malicious, report_link):
        super(IP, self).__init__(raw_data, last_analysis_results, malicious, suspicious)
        self.entity_id = entity_id
        self.as_owner = as_owner
        self.asn = asn
        self.continent = continent
        self.country = country
        self.last_analysis_stats = last_analysis_stats
        self.harmless = harmless
        self.undetected = undetected
        self.not_after = not_after
        self.not_before = not_before
        self.reputation = reputation
        self.tags = tags
        self.total_votes_harmless = total_votes_harmless
        self.total_votes_malicious = total_votes_malicious
        self.report_link = report_link
        self.widget_link = None
        self.widget_html = None

    def get_enrichment_data(self):
        return {
            'id': self.entity_id,
            'owner': self.as_owner,
            'asn': self.asn,
            'continent': self.continent,
            'country': self.country,
            'harmless_count': self.harmless,
            'malicious_count': self.malicious,
            'suspicious_count': self.suspicious,
            'undetected_count': self.undetected,
            'certificate_valid_not_after': self.not_after,
            'certificate_valid_not_before': self.not_before,
            'reputation': self.reputation,
            'tags': ', '.join(self.tags),
            'malicious_vote_count': self.total_votes_malicious,
            'harmless_vote_count': self.total_votes_harmless,
            'report_link': self.report_link,
            "widget_link": self.widget_link
        }

    def to_insight(self, threshold):
        detected = self.percentage_threshold if "%" in str(threshold) else self.threshold
        detected_string = f"{self.percentage_threshold}%" if "%" in str(threshold) else self.threshold
        content = ""
        content += "<table style='100%'><tbody>"
        content += "<tr><td style='text-align: left; width: 30%;'><strong style='font-size: 17px'>" \
                   "Detected: <span {threshold_style}> {threshold}</span></strong></td>" \
            .format(threshold_style=" style='color: #ff0000'" if detected else "", threshold=detected_string)
        content += "<td style='text-align: left; width: 30%;'><strong style='font-size: 17px'> Threshold: " \
                   "{}</strong></td></tr>".format(threshold)
        content += "</tbody></table><br>"
        content += "<table style='100%'><tbody>"
        content += "<tr><td style='text-align: left; width: 30%;'><strong>Owner: </strong></td>" \
                   "<td style='text-align: left; width: 30%'>{as_owner}</td></tr>".format(as_owner=self.as_owner)
        content += "<tr><td style='text-align: left; width: 30%;'><strong>ASN: </strong></td>" \
                   "<td style='text-align: left; width: 30%;'>{asn}</td></tr>".format(asn=self.asn)
        content += "<tr><td style='text-align: left; width: 30%;'><strong>Continent: </strong></td>" \
                   "<td style='text-align: left; width: 30%;'>{continent}</td></tr>".format(continent=self.continent)
        content += "<tr><td style='text-align: left; width: 30%;'><strong>Country: </strong></td>" \
                   "<td style='text-align: left; width: 30%;'>{country}</td></tr>".format(country=self.country)
        content += "<tr><td style='text-align: left; width: 30%;'><strong>Reputation: </strong></td>" \
                   "<td style='text-align: left; width: 30%;'>{reputation}</td></tr>".format(reputation=self.reputation)
        content += "<tr><td style='text-align: left; width: 30%;'><strong>Voted as malicious: </strong></td>" \
                   "<td style='text-align: left; width: 30%;'>{total_votes_malicious} times</td></tr>".format(
                    total_votes_malicious=self.total_votes_malicious)
        content += "</tbody></table><br><br>"
        content += "<p><strong>More Info: </strong>&nbsp; <a href={report_link} target='_blank'>{report_link}</a></p>".\
            format(report_link=self.report_link)

        return content


class Hash(VirusTotalEntity):
    def __init__(self, raw_data, entity_id, magic, md5, sha1, sha256, ssdeep, tlsh, vhash, meaningful_name, names,
                 last_analysis_results, harmless, malicious, suspicious, undetected, reputation, tags,
                 total_votes_harmless, total_votes_malicious, report_link, exiftool, file_type, file_description,
                 original_file_name, last_analysis_date):
        super(Hash, self).__init__(raw_data, last_analysis_results, malicious, suspicious)
        self.entity_id = entity_id
        self.magic = magic
        self.md5 = md5
        self.sha1 = sha1
        self.sha256 = sha256
        self.ssdeep = ssdeep
        self.tlsh = tlsh
        self.vhash = vhash
        self.meaningful_name = meaningful_name
        self.names = names
        self.last_analysis_results = last_analysis_results
        self.harmless = harmless
        self.malicious = malicious
        self.suspicious = suspicious
        self.undetected = undetected
        self.reputation = reputation
        self.tags = tags
        self.total_votes_harmless = total_votes_harmless
        self.total_votes_malicious = total_votes_malicious
        self.report_link = report_link
        self.exiftool = exiftool
        self.file_type = file_type
        self.file_description = file_description
        self.original_file_name = original_file_name
        self.last_analysis_date = last_analysis_date
        self.widget_link = None
        self.widget_html = None

    def get_enrichment_data(self):
        enrichment_data = {
            'id': self.entity_id,
            'magic': self.magic,
            'md5': self.md5,
            'sha1': self.sha1,
            'sha256': self.sha256,
            'ssdeep': self.ssdeep,
            'tlsh': self.tlsh,
            'vhash': self.vhash,
            'meaningful_name': self.meaningful_name,
            'names': ', '.join(self.names),
            'harmless_count': self.harmless,
            'malicious_count': self.malicious,
            'suspicious_count': self.suspicious,
            'undetected_count': self.undetected,
            'reputation': self.reputation,
            'tags': ', '.join(self.tags),
            'malicious_vote_count': self.total_votes_malicious,
            'harmless_vote_count': self.total_votes_harmless,
            'report_link': self.report_link,
        }

        enrichment_data.update(self.exiftool)

        return enrichment_data

    def to_insight(self, threshold):
        detected = self.percentage_threshold if "%" in str(threshold) else self.threshold
        detected_string = f"{self.percentage_threshold}%" if "%" in str(threshold) else self.threshold
        content = ""
        content += "<table style='100%'><tbody>"
        content += "<tr><td style='text-align: left; width: 30%;'><strong style='font-size: 17px'>" \
                   "Detected:  <span {threshold_style}>{threshold}</span></strong></td>" \
            .format(threshold_style=" style='color: #ff0000'" if detected else "", threshold=detected_string)
        content += "<td style='text-align: left; width: 30%;'><strong style='font-size: 17px'> Threshold: " \
                   "{}</strong></td></tr>".format(threshold)
        content += "</tbody></table><br>"

        content += "<table style='100%'><tbody>"
        content += "<tr><td style='text-align: left; width: 30%;'><strong>File Type: </strong></td>" \
                   "<td style='text-align: left; width: 30%'>{}</td></tr>".format(self.magic)
        content += "<tr><td style='text-align: left; width: 30%;'><strong>File Tags: </strong></td>" \
                   "<td style='text-align: left; width: 30%;'>{}</td></tr>".format(convert_list_to_comma_string(self.tags))
        content += "<tr><td style='text-align: left; width: 30%;'><strong>File Name: </strong></td>" \
                   "<td style='text-align: left; width: 30%;'>{}</td></tr>".format(self.meaningful_name)
        content += "<tr><td style='text-align: left; width: 30%;'><strong>Reputation: </strong></td>" \
                   "<td style='text-align: left; width: 30%;'>{}</td></tr>".format(self.reputation)
        content += "<tr><td style='text-align: left; width: 30%;'><strong>Voted as malicious: </strong></td>" \
                   "<td style='text-align: left; width: 30%;'>{} times</td></tr>".format(self.total_votes_malicious)
        content += "</tbody></table><br><br>"
        content += "<p><strong>More Info: </strong>&nbsp; <a href={report_link} target='_blank'>{report_link}</a></p>". \
            format(report_link=self.report_link)

        return content


class Comment(BaseModel):
    def __init__(self, raw_data, comment_id, date, comment, abuse_votes, positive_votes, negative_votes):
        super(Comment, self).__init__(raw_data)
        self.comment_id = comment_id
        self.date = date
        self.comment = comment
        self.abuse_votes = abuse_votes
        self.positive_votes = positive_votes
        self.negative_votes = negative_votes

    def to_table(self):
        return {
            "Date": self.date,
            "Comment": self.comment,
            "Abuse Votes": self.abuse_votes,
            "Negative Votes": self.negative_votes,
            "Positive Votes": self.positive_votes,
            "ID": self.comment_id
        }


class URL(VirusTotalEntity):
    def __init__(self, raw_data, entity_id, title, categories, last_http_response_code,
                 last_http_response_content_length, threat_names, last_analysis_stats, last_analysis_results, harmless,
                 malicious, suspicious, undetected, reputation, tags, total_votes_harmless, total_votes_malicious,
                 report_link, last_analysis_date):
        super(URL, self).__init__(raw_data, last_analysis_results, malicious, suspicious)
        self.entity_id = entity_id
        self.title = title
        self.categories = categories
        self.last_http_response_code = last_http_response_code
        self.last_http_response_content_length = last_http_response_content_length
        self.threat_names = threat_names
        self.last_analysis_stats = last_analysis_stats
        self.last_analysis_results = last_analysis_results
        self.harmless = harmless
        self.malicious = malicious
        self.suspicious = suspicious
        self.undetected = undetected
        self.reputation = reputation
        self.tags = tags
        self.total_votes_harmless = total_votes_harmless
        self.total_votes_malicious = total_votes_malicious
        self.report_link = report_link
        self.last_analysis_date = last_analysis_date
        self.widget_link = None
        self.widget_html = None

    def get_enrichment_data(self):
        enrichment_data = {
            "id": self.entity_id,
            "title": self.title,
            "last_http_response_code": self.last_http_response_code,
            "last_http_response_content_length": self.last_http_response_content_length,
            "threat_names": ', '.join(self.threat_names),
            "harmless_count": self.harmless,
            "malicious_count": self.malicious,
            "suspicious_count": self.suspicious,
            "undetected_count": self.undetected,
            "reputation": self.reputation,
            "tags": ', '.join(self.tags),
            "malicious_vote_count": self.total_votes_malicious,
            "harmless_vote_count": self.total_votes_harmless,
            "report_link": self.report_link,
            "widget_link": self.widget_link
        }

        enrichment_data.update(self.categories)

        return enrichment_data

    def to_insight(self, threshold):
        detected = self.percentage_threshold if "%" in str(threshold) else self.threshold
        detected_string = f"{self.percentage_threshold}%" if "%" in str(threshold) else self.threshold
        content = ""
        content += "<table style='100%'><tbody>"
        content += "<tr><td style='text-align: left; width: 30%;'><strong style='font-size: 17px'>" \
                   "Detected:  <span {threshold_style}>{threshold}</span></strong></td>" \
            .format(threshold_style=" style='color: #ff0000'" if detected else "", threshold=detected_string)
        content += "<td style='text-align: left; width: 30%;'><strong style='font-size: 17px'> Threshold: " \
                   "{}</strong></td></tr>".format(threshold)
        content += "</tbody></table><br>"
        content += "<table style='100%'><tbody>"
        content += "<tr><td style='text-align: left; width: 30%;'><strong>Title: </strong></td>" \
                   "<td style='text-align: left; width: 30%'>{}</td></tr>".format(self.title)
        content += "<tr><td style='text-align: left; width: 30%;'><strong>Status Code: </strong></td>" \
                   "<td style='text-align: left; width: 30%;'>{}</td></tr>".format(self.last_http_response_code)
        content += "<tr><td style='text-align: left; width: 30%;'><strong>Content Length: </strong></td>" \
                   "<td style='text-align: left; width: 30%;'>{}</td></tr>"\
            .format(self.last_http_response_content_length)
        for key, value in self.categories.items():
            content += "<tr><td style='text-align: left; width: 30%;'><strong>{key}: </strong></td>" \
                       "<td style='text-align: left; width: 30%;'>{value}</td></tr>"\
                .format(key=key, value=value)
        content += "<tr><td style='text-align: left; width: 30%;'><strong>Reputation: </strong></td>" \
                   "<td style='text-align: left; width: 30%;'>{}</td></tr>".format(self.reputation)
        content += "<tr><td style='text-align: left; width: 30%;'><strong>Voted as malicious: </strong></td>" \
                   "<td style='text-align: left; width: 30%;'>{} times</td></tr>".format(self.total_votes_malicious)
        content += "</tbody></table><br><br>"
        content += "<p><strong>More Info: </strong>&nbsp; <a href={report_link} target='_blank'>{report_link}</a></p>". \
            format(report_link=self.report_link)

        return content


class RuleMatch(BaseModel):
    def __init__(self, raw_data, id, level, source, title, description, match_context):
        super(RuleMatch, self).__init__(raw_data)
        self.id = id
        self.level = level
        self.source = source
        self.title = title
        self.description = description
        self.match_context = match_context


class SigmaAnalysis(BaseModel):
    def __init__(self, raw_data, rule_matches):
        super(SigmaAnalysis, self).__init__(raw_data)
        self.rule_matches = rule_matches

    def to_table(self):
        return [
            {
                "ID": item.id,
                "Severity": item.level,
                "Source": item.source,
                "Title": item.title,
                "Description": item.description,
                "Match Context": item.match_context
            }
            for item in self.rule_matches]


class Relation(BaseModel):
    def __init__(self, raw_data, url):
        super(Relation, self).__init__(raw_data)
        self.url = url


class RelatedIp(BaseModel):
    def __init__(self, raw_data, ip):
        super(RelatedIp, self).__init__(raw_data)
        self.ip = ip


class RelatedDomain(BaseModel):
    def __init__(self, raw_data, domain):
        super(RelatedDomain, self).__init__(raw_data)
        self.domain = domain


class Domain(VirusTotalEntity):
    def __init__(self, raw_data, entity_id, tags, categories, last_dns_records, last_analysis_stats,
                 last_analysis_results, harmless, malicious, suspicious, undetected, reputation, total_votes_harmless,
                 total_votes_malicious, whois, report_link):
        super(Domain, self).__init__(raw_data, last_analysis_results, malicious, suspicious)
        self.entity_id = entity_id
        self.tags = tags
        self.categories = categories
        self.last_dns_records = last_dns_records
        self.last_analysis_stats = last_analysis_stats
        self.harmless = harmless
        self.undetected = undetected
        self.reputation = reputation
        self.total_votes_harmless = total_votes_harmless
        self.total_votes_malicious = total_votes_malicious
        self.whois = whois
        self.report_link = report_link
        self.widget_link = None
        self.widget_html = None
        self.entity_type = None

    def get_enrichment_data(self):
        enrichment_data = {
            'id': self.entity_id,
            'harmless_count': self.harmless,
            'malicious_count': self.malicious,
            'suspicious_count': self.suspicious,
            'undetected_count': self.undetected,
            'reputation': self.reputation,
            'tags': ', '.join(self.tags),
            'malicious_vote_count': self.total_votes_malicious,
            'harmless_vote_count': self.total_votes_harmless,
            'report_link': self.report_link,
            "widget_link": self.widget_link
        }

        for key, value in self.categories.items():
            enrichment_data[f"category_{key}"] = value

        return enrichment_data

    def to_enrichment_data(self):
        clean_enrichment_data = {k: v for k, v in self.get_enrichment_data().items() if v}
        prefix = DATA_ENRICHMENT_PREFIX if self.entity_type == EntityTypes.HOSTNAME else "VT3_domain"
        return add_prefix_to_dict(clean_enrichment_data, prefix)

    def to_insight(self, threshold):
        detected = self.percentage_threshold if "%" in str(threshold) else self.threshold
        detected_string = f"{self.percentage_threshold}%" if "%" in str(threshold) else self.threshold
        content = ""
        content += "<table style='100%'><tbody>"
        content += "<tr><td style='text-align: left; width: 30%;'><strong style='font-size: 17px'>" \
                   "Detected: <span {threshold_style}> {threshold}</span></strong></td>" \
            .format(threshold_style=" style='color: #ff0000'" if detected else "", threshold=detected_string)
        content += "<td style='text-align: left; width: 30%;'><strong style='font-size: 17px'>Threshold: " \
                   "{}</strong></td></tr>".format(threshold)
        content += "</tbody></table><br>"
        content += "<table style='100%'><tbody>"

        content += "<tr><td style='text-align: left; width: 30%;'><strong>Reputation: </strong></td>" \
                   "<td style='text-align: left; width: 30%;'>{}</td></tr>".format(self.reputation)
        content += "<tr><td style='text-align: left; width: 30%;'><strong>Voted as malicious: </strong></td>" \
                   "<td style='text-align: left; width: 30%;'>{} times</td></tr>".format(self.total_votes_malicious)
        content += "</tbody></table><br><br>"

        content += "<p><strong>DNS Records: </strong></p>"
        content += "<table><tbody>"
        content += "<tr><td style='text-align: left; width: 30%;'><strong>Type</strong></td>"
        content += "<td style='text-align: left; width: 30%;'><strong>Value</strong></td>"
        content += "<td style='text-align: left; width: 30%;'><strong>TTL</strong></td></tr>"
        for dns_record in self.last_dns_records:
            content += "<tr><td style='text-align: left; width: 30%;'>{}</td>".format(dns_record.type)
            content += "<td style='text-align: left; width: 30%;'>{}</td>".format(dns_record.ttl)
            content += "<td style='text-align: left; width: 30%;'>{}</td></tr>".format(dns_record.value)
        content += "</tbody></table><br>"

        content += "<p><strong>Whois</strong></p>"
        content += "<p>{}</p><br>".format(self.whois.replace('\n', '</p><p>'))

        content += "<p><strong>More Info: </strong>&nbsp; <a href={report_link} target='_blank'>{report_link}</a></p>".\
            format(report_link=self.report_link)

        return content


class RelatedHash(BaseModel):
    def __init__(self, raw_data, file_hash):
        super(RelatedHash, self).__init__(raw_data)
        self.file_hash = file_hash


class Graph(BaseModel):
    def __init__(self, raw_data, attributes, graph_id, links=None):
        super(Graph, self).__init__(raw_data)
        self.attributes = attributes
        self.graph_id = graph_id
        self.links = links

    def to_json_shorten(self):
        return {
            'attributes': self.attributes,
            'id': self.graph_id
        }

    def to_table(self):
        return [
            {
                "Source": item.source,
                "Target": item.target,
                "Connection Type": item.connection_type,
            }
            for item in self.links]


class Link(BaseModel):
    def __init__(self, raw_data, connection_type, source, target):
        super(Link, self).__init__(raw_data)
        self.connection_type = connection_type
        self.source = source
        self.target = target


class Ioc(VirusTotalEntity):
    def __init__(self, raw_data, last_analysis_results):
        super(Ioc, self).__init__(raw_data, last_analysis_results, None, None)
        self.last_analysis_results = last_analysis_results

    @staticmethod
    def to_case_wall_link(ioc_type, ioc):
        return IOC_LINK_STRUCTURE.format(ioc_type=IOC_LINK_ITEMS_MAPPING.get(ioc_type), ioc=ioc)


class Sandbox(BaseModel):
    def __init__(self, raw_data):
        super(Sandbox, self).__init__(raw_data)


class Notification(VirusTotalEntity):
    def __init__(self, raw_data, id, meaningful_name, rule_name, notification_date, last_analysis_stats,
                 last_analysis_results, malicious, suspicious):
        super(Notification, self).__init__(raw_data, last_analysis_results, malicious, suspicious)
        self.id = id
        self.meaningful_name = meaningful_name
        self.last_analysis_stats = last_analysis_stats
        self.rule_name = rule_name
        self.notification_date = notification_date
        self.timestamp_ms = self.notification_date*1000

    def get_alert_info(self, alert_info, environment_common, device_product_field):
        alert_info.environment = environment_common.get_environment(dict_to_flat(self.to_json()))
        alert_info.ticket_id = self.id
        alert_info.display_id = self.id
        alert_info.name = self.meaningful_name or FALLBACK_NAME
        alert_info.device_vendor = DEVICE_VENDOR
        alert_info.device_product = self.raw_data.get(device_product_field) or DEVICE_PRODUCT
        alert_info.priority = self.get_severity()
        alert_info.rule_generator = self.rule_name
        alert_info.source_grouping_identifier = self.rule_name
        alert_info.end_time = alert_info.start_time = self.timestamp_ms
        alert_info.events = self.to_events()

        return alert_info

    def get_severity(self):
        if self.malicious:
            return 100
        elif self.suspicious:
            return 60
        return 40

    def to_events(self):
        return [dict_to_flat(self.raw_data)]
