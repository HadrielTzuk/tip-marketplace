PROVIDER_NAME = u"Cylance"

# Actions
GET_THREAT_DOWNLOAD_LINK = u"{} - Get Threat Download Link".format(PROVIDER_NAME)

ENDPOINTS = {
    u"get_threat_download_link": u"/threats/v2/download/{hash}"
}
PARAMETERS_DEFAULT_DELIMITER = u","
ENRICH_PREFIX = u"Cylance"
