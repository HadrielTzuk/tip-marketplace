INTEGRATION_NAME = "Mandiant"

PING_SCRIPT_NAME = f"{INTEGRATION_NAME} - Ping"
ENRICH_ENTITIES_SCRIPT_NAME = f"{INTEGRATION_NAME} - Enrich Entities"
GET_RELATED_ENTITIES_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Related Entities"
ENRICH_IOCS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Enrich IOCs"
GET_MALWARE_DETAILS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Malware Details"


MAX_SEVERITY_SCORE = 100
DEFAULT_LIMIT = 100
PAGE_SIZE = 100

INDICATOR_URL = "/indicator/{type}/{value}"
ACTOR_URL = "/actors/{id}"
VULNERABILITY_URL = "/cve/{id}"
MALWARE_URL = "/malware/{id}"

ENRICHMENT_PREFIX = "Mandiant"
MALWARE_TABLE_NAME = "Malware Results"
MALWARE_TYPE = "malware"
THREAT_ACTOR_TYPE = "threat-actor"
MALWARE_TYPE_PART = "malware-"
VULNERABILITY_TYPE_PART = "CVE-"
THREAT_ACTOR_TYPE_PART = "threat-actor-"

INDICATOR_TYPE_MAPPING = {
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "hash": "hash",
    "ipv4": "ip",
    "ipv6": "ip",
    "fqdn": "fqdn",
    "url": "url"
}

IOC_MAPPING = {
    "HOSTNAME": ["fqdn"],
    "ADDRESS": ["ipv4", "ipv6"],
    "DestinationURL": ["url"],
    "FILEHASH": ["hash", "md5", "sha1", "sha256"]
}
RELATED_ENTITIES_DICT = {
    "hash": [],
    "url": [],
    "fqdn": [],
    "ip": [],
    "email": []
}
