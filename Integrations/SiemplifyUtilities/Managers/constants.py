PROVIDER_NAME = "SiemplifyUtilities"

# Actions name
PARSE_EML_TO_JSON_SCRIPT_NAME = "{} - Parse EML to JSON".format(PROVIDER_NAME)
EXPORT_ENTITIES_AS_OPENIOC_FILE_SCRIPT_NAME = u"Export Entities as OpenIOC file"

PARAMETERS_DEFAULT_DELIMITER = ","
MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
LOCALHOST = u'127.0.0.1'

IOC_STRING_CONTENT_TYPE = u"string"
IOC_BOOL_CONTENT_TYPE = u"bool"

MD5_HASH_LENGTH = 32
SHA1_HASH_LENGTH = 40
SHA256_HASH_LENGTH = 64
IOC_EXTENSION = u"ioc"
IOC_FILE_DESCRIPTION = u"Siemplify Generated IOC"
IOC_FILE_AUTHOR = u"Siemplify"
NUMERIC_REGEX = r'^\d+$'
UNDERSCORE = u"_"
# IOC
MD5_HASH = u"md5"
SHA1_HASH = u"sha1"
SHA256_HASH = u"sha256"
IP_ADDRESS = u"ip_address"
DOMAIN = u"domain"
HOSTNAME = u"hostname"
IS_USER_ENABLED = u"is_enabled"
MAC_ADDRESS = u"mac_address"
OS = u"os"
ASSET_TYPE = u"asset_type"
PROCESSOR = u"processor"
USERNAME = u"username"
MEMORY = u"memory"
USER_GROUPS = u"groups"
USER_EMAIL = u"email"
USER_DISPLAY_NAME = u"display_name"
URL = u"url"
HOST_MEMORY = u"memory"
HOST_OS_VERSION = u"os_version"
IOC_MAPPINGS = {  # IOC search term type and text
    MD5_HASH: (IOC_STRING_CONTENT_TYPE, u"FileItem/Md5sum"),
    SHA1_HASH: (IOC_STRING_CONTENT_TYPE, u"FileItem/Sha1sum"),
    SHA256_HASH: (IOC_STRING_CONTENT_TYPE, u"FileItem/Sha256sum"),
    IP_ADDRESS: (IOC_STRING_CONTENT_TYPE, u"DnsEntryItem/RecordData/IPv4Address"),
    IS_USER_ENABLED: (IOC_BOOL_CONTENT_TYPE, u"UserItem/disabled"),
    DOMAIN: (IOC_STRING_CONTENT_TYPE, u"SystemInfoItem/domain"),
    HOSTNAME: (IOC_STRING_CONTENT_TYPE, u"DnsEntryItem/HOST"),
    MAC_ADDRESS: (IOC_STRING_CONTENT_TYPE, u"SystemInfoItem/MAC"),
    OS: (IOC_STRING_CONTENT_TYPE, u"SystemInfoItem/OS"),
    ASSET_TYPE: (IOC_STRING_CONTENT_TYPE, u"DnsEntryItem/RecordData/Type"),
    PROCESSOR: (IOC_STRING_CONTENT_TYPE, u"SystemInfoItem/processor"),
    USERNAME: (IOC_STRING_CONTENT_TYPE, u"UserItem/Username"),
    USER_GROUPS: (IOC_STRING_CONTENT_TYPE, u"UserItem/grouplist/groupname"),
    USER_EMAIL: (IOC_STRING_CONTENT_TYPE, u"UserItem/userid"),
    USER_DISPLAY_NAME: (IOC_STRING_CONTENT_TYPE, u"UserItem/fullname"),
    HOST_MEMORY: (IOC_STRING_CONTENT_TYPE, u"SystemInfoItem/totalphysical"),
    HOST_OS_VERSION: [(IOC_STRING_CONTENT_TYPE, u"SystemInfoItem/kernelVersion"), (IOC_STRING_CONTENT_TYPE, u"SystemInfoItem/biosInfo/biosVersion")],
    URL: (IOC_STRING_CONTENT_TYPE, u"UrlHistoryItem/URL")
}
NEGATABLE_IOCS = [IS_USER_ENABLED]
