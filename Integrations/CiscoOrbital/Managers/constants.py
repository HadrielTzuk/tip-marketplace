PROVIDER_NAME = "Cisco Orbital"
API_ROOT = "https://orbital.amp.cisco.com/"

ENDPOINTS = {
    "generate_token": "v0/oauth2/token",
    "test_connectivity": "v0/ok",
    "submit_query": "v0/query",
    "get_results": "v0/jobs/{job_id}/results"
}

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(PROVIDER_NAME)
EXECUTE_QUERY_SCRIPT_NAME = "{} - Execute Query".format(PROVIDER_NAME)


MAX_EXPIRATION_IN_HOURS = 24
MIN_EXPIRATION_IN_MINUTES = 1
ASYNC_ACTION_TIMEOUT_THRESHOLD_MS = 40 * 1000
IPV4_TYPE = "ipv4"
IPV6_TYPE = "ipv6"
NAME_DEFAULT_STRUCTURE = "Siemplify-{}"
