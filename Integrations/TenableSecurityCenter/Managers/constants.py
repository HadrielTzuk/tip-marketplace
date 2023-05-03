PROVIDER_NAME = "TenableSecurityCenter"

# Actions
RUN_ASSET_SCAN_SCRIPT_NAME = "{} - Run Asset Scan".format(PROVIDER_NAME)
CREATE_IP_LIST_ASSET_SCRIPT_NAME = "{} - Create IP List Asset".format(PROVIDER_NAME)
ADD_IP_TO_LIST_ASSET_SCRIPT_NAME = "{} - Add IP To IP List Asset".format(PROVIDER_NAME)


ENDPOINTS = {
    u"get_assets": u"/rest/asset",
    u"scan": u"/rest/scan",
    u'asset_details': u"/rest/asset/{asset_id}"
}


UNIX_FORMAT = 1
DATETIME_FORMAT = 2
DAY_IN_MILLISECONDS = 86400000
