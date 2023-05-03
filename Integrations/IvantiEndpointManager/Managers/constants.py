INTEGRATION_NAME = "IvantiEndpointManager"
INTEGRATION_DISPLAY_NAME = "Ivanti Endpoint Manager"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
LIST_QUERIES_SCRIPT_NAME = "{} - List Queries".format(INTEGRATION_DISPLAY_NAME)
LIST_DELIVERY_METHODS_SCRIPT_NAME = "{} - List Delivery Methods".format(INTEGRATION_DISPLAY_NAME)
LIST_COLUMN_SET_FIELDS_SCRIPT_NAME = "{} - List Column Set Fields".format(INTEGRATION_DISPLAY_NAME)
ENRICH_ENTITIES_SCRIPT_NAME = "{} - Enrich Entities".format(INTEGRATION_DISPLAY_NAME)
LIST_ENDPOINT_VULNERABILITIES_SCRIPT_NAME = "{} - List Endpoint Vulnerabilities".format(INTEGRATION_DISPLAY_NAME)
LIST_PACKAGES_SCRIPT_NAME = "{} - List Packages".format(INTEGRATION_DISPLAY_NAME)
LIST_COLUMN_SETS_SCRIPT_NAME = "{} - List Column Sets".format(INTEGRATION_DISPLAY_NAME)
EXECUTE_QUERY_SCRIPT_NAME = "{} - Execute Query".format(INTEGRATION_DISPLAY_NAME)
EXECUTE_TASK_SCRIPT_NAME = "{} - Execute Task".format(INTEGRATION_DISPLAY_NAME)
SCAN_ENDPOINTS_SCRIPT_NAME = "{} - Scan Endpoints".format(INTEGRATION_DISPLAY_NAME)

ENDPOINTS = {
    "ping": "/MBSDKService/MsgSDK.asmx/WhoAmI",
    "list_queries": "/MBSDKService/MsgSDK.asmx/ListQueries",
    "list_delivery_method": "/MBSDKService/MsgSDK.asmx/ListDeliveryMethod?DeliveryType={type}",
    "list_column_set_fields": "/MBSDKService/MsgSDK.asmx/ListColumnSetColumns?columnset={column_set}",
    "list_machines": "/MBSDKService/MsgSDK.asmx/ListMachines",
    "get_machine_data": "/MBSDKService/MsgSDK.asmx/GetMachineData",
    "get_vulnerabilities": "/MBSDKService/MsgSDK.asmx/GetMachineVulnerabilities?GUID={guid}",
    "list_packages": "/MBSDKService/MsgSDK.asmx/ListDistributionPackages?PkgType=ALL",
    "list_column_sets": "/MBSDKService/MsgSDK.asmx/ListColumnSets",
    "execute_query": "/MBSDKService/MsgSDK.asmx/RunQuery?queryName={query_name}",
    "create_task": "/MBSDKService/MsgSDK.asmx/CreateTask",
    "start_task": "/MBSDKService/MsgSDK.asmx/StartTaskNow",
    "get_task_result": "/MBSDKService/MsgSDK.asmx/GetTaskMachineStatus",
    "create_scan": "/MBSDKService/MsgSDK.asmx/ScanForVulnerabilities",
    "add_device_to_task": "/MBSDKService/MsgSDK.asmx/AddDeviceToScheduledTask"
}

FILTER_LOGIC = {
    "equal": "Equal",
    "contains": "Contains",
    "in_list": "In list"
}

DELIVERY_METHOD_TYPES = {
    "Push": "PUSH",
    "Pull": "PULL",
    "Push and Pull": "PUSHANDPULL",
    "Multicast": "MULTICAST",
    "All": "ALL",
}

SEVERITY_CODES = {
    "ServicePack": "0",
    "Critical": "1",
    "High": "2",
    "Medium": "3",
    "Low": "4",
    "N/A": "5",
    "Unknown": "6"
}

DEFAULT_TASK_NAME = "Siemplify Execute Task"
DEFAULT_SCAN_NAME = "Siemplify Scan Endpoints"
DONE_STATUS = "Done"
FAILED_STATUS = "Failed"
DEFAULT_TIMEOUT = 300
