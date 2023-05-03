# ============================================================================#
# title           :VirusTotalParser.py
# description     :This Module contains the VirusTotalParser from the raw data based on the data models
# author          :gegham.jivanyan@siemplify.co
# date            :13-12-2019
# python_version  :2.7
# libraries       :
# requirements    :
# product_version :
# ============================================================================#


# ============================= IMPORTS ===================================== #


from datamodels import IP, Domain, URL, HASH, Comment


# ============================= CLASSES ===================================== #


#
class VirusTotalParserError(Exception):
    """
    General Exception for VirusTotalParser class.
    """
    pass


#
class VirusTotalParser(object):
    """
    VirusTotalParser class.
    Build objects of classes defined in data models.
    """

    #
    def __init__(self, siemplify_logger=None):
        self.siemplify_logger = siemplify_logger

    #
    @staticmethod
    def build_ip_address_object(report):
        """
        Build IP address object.
        :param report: {dict} report with ip address information
        :return: IP object
        """
        return IP(
            raw_data=report,
            asn=report.get(u'asn'),
            country=report.get(u'country'),
            positives=VirusTotalParser.__get_max_of_positives(report),
            resolutions=report.get(u'resolutions'),
            detected_urls=report.get(u'detected_urls'),
            detected_downloaded_samples=report.get(u'detected_downloaded_samples', []),
            detected_referrer_samples=report.get(u'detected_referrer_samples', []),
            detected_communicating_samples=report.get(u'detected_communicating_samples', []),
            undetected_urls=report.get(u'undetected_urls'),
            undetected_downloaded_samples=report.get(u'undetected_downloaded_samples')
        )

    @staticmethod
    def __get_max_of_positives(report):
        mixed_data = report.get(u'detected_urls', []) + report.get(u'detected_downloaded_samples', []) + \
                     report.get(u'detected_referrer_samples', []) + report.get(u'detected_communicating_samples', [])
        positives = [item.get('positives', 0)
                     for item in mixed_data]

        return max(positives) if positives else 0

    #
    @staticmethod
    def build_url_object(report):
        """
        Build URL object.
        :param report: {dict} report with url information
        :return: URL object
        """
        return URL(
            raw_data=report,
            scan_id=report.get(u'scan_id'),
            scan_date=report.get(u'scan_date'),
            url=report.get(u'url'),
            permalink=report.get(u'permalink'),
            total=report.get(u'total'),
            positives=report.get(u'positives'),
            scans=report.get(u'scans'),
            response_code=report.get(u'response_code'),
            first_seen=report.get(u"first_seen"),
            last_seen=report.get(u"last_seen"),
            resource=report.get(u"resource")
        )

    #
    @staticmethod
    def build_hash_object(report):
        """
        Build Hash object.
        :param report: {dict} report with hash information
        :return: HASH object
        """
        return HASH(
            raw_data=report,
            response_code=report.get(u'response_code'),
            md5=report.get(u'md5'),
            sha1=report.get(u'sha1'),
            scan_id=report.get(u'scan_id'),
            scan_date=report.get(u'scan_date'),
            permalink=report.get(u'permalink'),
            positives=report.get(u'positives'),
            total=report.get(u'total'),
            scans=report.get(u'scans'),
            resource=report.get(u"resource"),
            sha256=report.get(u"sha256"),
            ssdeep=report.get(u"ssdeep"),
            authentihash=report.get(u"authentihash"),
            type=report.get(u"type"),
            imphash=report.get(u"additional_info", {}).get(u"pe-imphash"),
            size=report.get(u"size"),
            magic=report.get(u"additional_info", {}).get(u"magic"),
            tags=report.get(u"tags"),
            first_seen=report.get(u"first_seen"),
            last_seen=report.get(u"last_seen"),
            submission_names=report.get(u"submission_names"),
        )

    @staticmethod
    def build_comment_object(comment):
        """
        Build Hash object.
        :param report: {dict} report with hash information
        :return: HASH object
        """
        return Comment(
            raw_data=comment,
            date=comment.get(u'date'),
            comment=comment.get(u'comment')
        )

    #
    @staticmethod
    def build_domain_object(report):
        """
        Build Domain object.
        :param report: {dict} report with domain information
        :return: Domain object
        """

        return Domain(
            raw_data=report,
            undetected_referrer_samples=report.get(u'undetected_referrer_samples'),
            whois_timestamp=report.get(u'whois_timestamp'),
            detected_referrer_samples=report.get(u'detected_referrer_samples'),
            resolutions=report.get(u'resolutions'),
            subdomains=report.get(u'subdomains'),
            categories=report.get(u'categories'),
            domain_siblings=report.get(u'domain_siblings'),
            undetected_urls=report.get(u'undetected_urls'),
            detected_urls=report.get(u'detected_urls'),
            bitdefender_category=report.get(u'bitdefender_category'),
            forcepoint_threatseeker_category=report.get(u'forcepoint_threatseeker_category'),
            alexa_category=report.get(u'alexa_category'),
            alexa_domain_info=report.get(u'alexa_domain_info'),
            bitdefender_domain_info=report.get(u'bitdefender_domain_info')
        )

    #
    @staticmethod
    def get_scan_id(report):
        """
            return scan_id from response.
            :param report: {dict} report with domain information
            :return: scan_id
        """
        return report.get(u'scan_id')
