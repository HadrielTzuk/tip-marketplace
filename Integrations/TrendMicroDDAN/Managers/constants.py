INTEGRATION_NAME = "TrendMicroDDAN"
INTEGRATION_DISPLAY_NAME = "Trend Micro DDAN"

# Actions
PING_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Ping"
SUBMIT_FILE_URL_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Submit File URL"
SUBMIT_FILE_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Submit File"


ENDPOINTS = {
    "register": "/web_service/sample_upload/register",
    "unregister": "/web_service/sample_upload/unregister",
    "test_connection": "/web_service/sample_upload/test_connection",
    "check_duplicate_sample": "/web_service/sample_upload/check_duplicate_sample",
    "upload_sample": "/web_service/sample_upload/simple_upload_sample",
    "get_report": "/web_service/sample_upload/get_report",
    "get_suspicious_object": "/web_service/sample_upload/get_suspicious_object_by_sha1",
    "get_event_log": "/web_service/sample_upload/get_event_log",
    "get_sandbox_screenshot": "/web_service/sample_upload/get_sandbox_screenshot",
}

PRODUCT_NAME = "ChronicleSOAR"
SOURCE_NAME = "ChronicleSOARIntegration"

SAMPLE_TYPE = {
    "file": "0",
    "url": "1"
}

IN_PROGRESS_STATUS_CODE = 102
NOT_FOUND_STATUS_CODE = 421

LINE_BREAK = "\n"
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
