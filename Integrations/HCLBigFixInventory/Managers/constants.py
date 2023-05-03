INTEGRATION_NAME = "HCL BigFix Inventory"
INTEGRATION_DISPLAY_NAME = "HCL BigFix Inventory"

# Actions
PING_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Ping"
ENRICH_ENTITIES_SCRIPT_NAME = f"{INTEGRATION_NAME} - Enrich Entities"

ENDPOINTS = {
    "ping": "/api/sam/about",
    "get_devices": "/api/sam/v2/computers"
}

ENRICHMENT_PREFIX = "HCLBigFixInv"
