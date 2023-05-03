AVAILABLE_STATUSES = [u"Unknown", u"New", u"InProgress", u"Resolved"]
AVAILABLE_SEVERITIES = [u"UnSpecified", u"Informational", u"Low", u"Medium", u"High"]

DEFAULT_ALERTS_LIMIT = 100
DEFAULT_VENDOR_NAME = u"Microsoft"
DEFAULT_PRODUCT_NAME = u"Microsoft Defender ATP"

STORED_IDS_LIMIT = 3000

ACTION_PARAM_MAPPING = {
    "Block": "Block",
    "Audit": "Audit",
    "Block And Remediate": "BlockAndRemediate",
    "Allow": "Allowed"
}

SHA256_LENGTH = 64
MD5_LENGTH = 32
SHA1_LENGTH = 40

POSSIBLE_INDICATOR_TYPES = ["FileSha1", "FileSha256", "FileMd5", "CertificateThumbprint", "IpAddress", "DomainName",
                            "Url"]
POSSIBLE_ACTION_TYPES = ["Warn", "Block", "Audit", "Alert", "AlertAndBlock", "BlockAndRemediate", "Allowed"]
POSSIBLE_SEVERITIES = ["Informational", "Low", "Medium", "High"]
