# ============================================================================#
# title           :datamodels.py
# description     :This module contains the DataModel for VirusTotal objects
# author          :gegham.jivanyan@siemplify.co
# date            :13-12-2019
# python_version  :2.7
# libraries       :
# requirements    :
# product_version :
# ============================================================================#

# =====================================
#              IMPORTS                #
# =====================================

from SiemplifyUtils import utc_now

# ============================= CLASSES ===================================== #

TIME_FORMAT = u"%Y-%m-%d %H:%M:%S"


class Comment(object):
    """
    Comment dataclass
    """

    def __init__(self, raw_data=None, date=None, comment=None):
        self.raw_data = raw_data
        self.comment = comment
        self.date = date

    def to_enrichment_data(self):
        self.to_csv()

    def to_json(self):
        return self.raw_data

    def to_csv(self):
        return {
            u"Date": self.date,
            u"Comment": self.comment
        }


class IP(object):
    """
    IP dataclass
    """

    def __init__(self, raw_data=None, asn=None, country=None, positives=None,
                 resolutions=None, detected_urls=None, detected_referrer_samples=None, detected_downloaded_samples=None,
                 detected_communicating_samples=None, undetected_urls=None, undetected_downloaded_samples=None):
        self.raw_data = raw_data
        self.asn = asn
        self.country = country
        self.positives = positives
        self.resolutions = resolutions
        self.detected_urls = detected_urls
        self.detected_referrer_samples = detected_referrer_samples
        self.detected_downloaded_samples = detected_downloaded_samples
        self.detected_communicating_samples = detected_communicating_samples
        self.undetected_urls = undetected_urls
        self.undetected_downloaded_samples = undetected_downloaded_samples

    def __get_related_domains(self):
        return u", ".join([resolution[u'hostname'] for resolution in self.resolutions]) if self.resolutions else None

    #
    def to_enrichment_data(self):
        return {
            u'Country': self.country,
            u'Related Domains': self.__get_related_domains(),
            u'Latest_scan_date': utc_now().strftime(TIME_FORMAT)
        }

    #
    def to_json(self):
        return self.raw_data


#
class Domain(object):
    """
    Domain dataclass
    """

    def __init__(self, raw_data=None, undetected_referrer_samples=None, whois_timestamp=None,
                 detected_referrer_samples=None, resolutions=None, subdomains=None, categories=None,
                 domain_siblings=None, undetected_urls=None, detected_urls=None, bitdefender_category=None,
                 forcepoint_threatseeker_category=None, alexa_category=None, alexa_domain_info=None,
                 bitdefender_domain_info=None):
        self.raw_data = raw_data
        self.undetected_referrer_samples = undetected_referrer_samples
        self.whois_timestamp = whois_timestamp
        self.detected_referrer_samples = detected_referrer_samples
        self.resolutions = resolutions
        self.subdomains = subdomains
        self.categories = categories
        self.domain_siblings = domain_siblings
        self.undetected_urls = undetected_urls
        self.detected_urls = detected_urls
        self.bitdefender_category = bitdefender_category
        self.forcepoint_threatseeker_category = forcepoint_threatseeker_category
        self.alexa_category = alexa_category
        self.alexa_domain_info = alexa_domain_info
        self.bitdefender_domain_info = bitdefender_domain_info

    def __get_related_categories(self):
        return u', '.join(self.categories) if isinstance(self.categories, list) else self.categories

    def to_enrichment_data(self):
        """
        Build Domain enrichment object.
        :return: {dict} enrichment object.
        """
        return {
            u'Categories': self.__get_related_categories(),
            u'Bit Defender Category': self.bitdefender_category,
            u'Bit Defender Domain Info': self.bitdefender_domain_info,
            u'Alexa Category': self.alexa_category,
            u'Alexa Domain Info': self.alexa_domain_info,
            u'Force Point ThreatSeeker Category': self.forcepoint_threatseeker_category,
            # last scan date is the current time
            u'Latest_scan_date': utc_now().strftime(TIME_FORMAT)
        }

    def to_json(self):
        return self.raw_data


class BaseUrlOrHash(object):
    def __init__(self, raw_data=None, scan_id=None, scan_date=None, permalink=None, resource=None,
                 positives=None, total=None, scans=None, response_code=None, first_seen=None, last_seen=None):
        self.raw_data = raw_data
        self.resource = resource
        self.scan_id = scan_id
        self.scan_date = scan_date
        self._permalink = permalink
        self._positives = positives
        self._total = total
        self.response_code = response_code
        self.scans = scans
        self.first_seen = first_seen
        self.last_seen = last_seen

    def __get_related_scans(self):
        return u", ".join([engine for engine in self.scans if self.scans.get(engine, {}).get(u'detected')]) if self.scans else None

    def to_json(self):
        return self.raw_data

    @property
    def positives(self):
        return self._positives

    @positives.setter
    def positives(self, value):
        self._positives = value

    @property
    def permalink(self):
        return self._permalink

    @property
    def total(self):
        return self._total

    def build_engine_csv(self):
        """
        The csv contain all engines which scanned url/file and their detection status.
        :return: {list} all engines which scanned the entity and their detection status.
        """
        engine_csvs = []

        if not self.scans:
            return engine_csvs

        for key, value in self.scans.items():
            engine_csv = {}
            engine_csv[u'Engine'] = key
            engine_csv[u'Is Malicious'] = value.get(u'detected')
            engine_csv[u'Result'] = value.get(u'result')
            engine_csv[u'Last Analysis'] = value.get(u'update')
            engine_csvs.append(engine_csv)

        return engine_csvs

    def create_enrichment_data(self):
        return {
            u'Scan ID': self.scan_id,
            u'Resource': self.resource,
            u'Scan Date': self.scan_date,
            u'Permalink': self.permalink,
            u"Total": self.total,
            u'Risk Score': u"{}/{}".format(self.positives, self.total),
            u"Positives": self.positives,
            u"First Submission": self.first_seen,
            u"Last Submission": self.last_seen,
            u'Detecting Engines': self.__get_related_scans()
        }

    @positives.setter
    def positives(self, value):
        self._positives = value

    @permalink.setter
    def permalink(self, value):
        self._permalink = value

    @total.setter
    def total(self, value):
        self._total = value


class HASH(BaseUrlOrHash):
    """
    Hash dataclass
    """

    def __init__(self, raw_data=None, permalink=None, scan_id=None, sha256=None,
                 md5=None, sha1=None, scan_date=None, positives=None, total=None, scans=None, response_code=None,
                 ssdeep=None, authentihash=None, type=None, imphash=None, size=None, magic=None, tags=None,
                 submission_names=None, resource=None, first_seen=None, last_seen=None):
        super(HASH, self).__init__(raw_data, scan_id, scan_date, permalink, resource, positives, total, scans,
                                   response_code, first_seen, last_seen)
        self.sha256 = sha256
        self.md5 = md5
        self.sha1 = sha1
        self.ssdeep = ssdeep
        self.authentihash = authentihash
        self.type = type
        self.imphash = imphash
        self.size = size
        self.magic = magic
        self.tags = tags
        self.submission_names = submission_names

    def to_enrichment_data(self):
        enrichment_data = self.create_enrichment_data()
        enrichment_data.update(
            {
                u'MD5': self.md5,
                u'SHA1': self.sha1,
                u'SHA256': self.sha256,
                u'SSDeep': self.ssdeep,
                u'Authentihash': self.authentihash,
                u'File Type': self.type,
                u'Imphash': self.imphash,
                u'File Size': self.size,
                u'Magic Literal': self.magic,
                u'Tags': u','.join(self.tags) if self.tags else None,
                u'First Submission': self.first_seen,
                u'Last Submission': self.last_seen,
                u'Filename': u','.join(self.submission_names) if self.submission_names else None
            }
        )
        return enrichment_data


class URL(BaseUrlOrHash):
    """
    URL dataclass
    """

    def __init__(self, raw_data=None, scan_id=None, scan_date=None, url=None, permalink=None,
                 total=None, positives=None, scans=None, response_code=None, resource=None, first_seen=None,
                 last_seen=None):
        super(URL, self).__init__(raw_data, scan_id, scan_date, permalink, resource, positives, total, scans,
                                  response_code, first_seen, last_seen)
        self.url = url

    #
    def to_enrichment_data(self):
        enrichment_data = self.create_enrichment_data()
        enrichment_data.update({u'Scanned URL': self.url})
        return enrichment_data
