INTEGRATION_NAME = "SymantecEmailSecurityCloud"
INTEGRATION_DISPLAY_NAME = "Symantec Email Security.Cloud"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
BLOCK_ENTITIES_SCRIPT_NAME = "{} - Block Entities".format(INTEGRATION_DISPLAY_NAME)

ENDPOINTS = {
    "ping": "/domains/global/iocs/download",
    "block_entities": "/domains/global/iocs/upload?api-list-action=MERGE"
}

IOC_TYPES_MAPPING = {
    "DestinationURL": ["url"],
    "FILEHASH": {
        "MD5": ["md5attachment"],
        "SHA256": ["sha2attachment"]
    },
    "ADDRESS": ["senderipaddress"],
    "HOSTNAME": ["bodysenderdomain", "envelopesenderdomain"],
    "EMAILSUBJECT": ["subject"],
    "USERUNIQNAME": ["envelopesenderemail", "bodysenderemail"]
}

REMEDIATION_MAPPING = {
    "Block and Delete": "B",
    "Quarantine": "Q",
    "Redirect": "M",
    "Tag Subject": "T",
    "Append Header": "H"
}
DEFAULT_REMEDIATION = "Block and Delete"
SHA256_LENGTH = 64
MD5_LENGTH = 32
