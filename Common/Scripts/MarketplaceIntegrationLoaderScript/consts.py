
# API REQUEST CONSTS
IDE_API = "/api/external/v1/ide"
ACCOUNTS_API = "/api/external/v1/accounts"
INTEGRATIONS_API = "/api/external/v1/integrations"
STORE_API = "/api/external/v1/store"

REQUEST_TIMEOUT = 90

ENDPOINTS = {
    "login": f"{ACCOUNTS_API}/Login?format=camel",
    "get-package-details": f"{IDE_API}/GetPackageDetails?format=camel",
    "import-package": f"{IDE_API}/ImportPackage?format=camel",
    "get-installed-integrations": f"{INTEGRATIONS_API}/GetInstalledIntegrations?format=camel",
    "export-usecase": f"{STORE_API}/ExportUseCase?format=camel",
    "import-usecase": f"{STORE_API}/ImportUsecaseZipFile?format=camel"
}
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, */*"
}

# ZIP CONSTS
VALID_EXTENSIONS = [".py", ".def", ".actiondef", ".connectordef", ".orch"
                    ".jobdef", ".whl", ".tar.gz", ".json"]
INVALID_EXTENSIONS = [".fulldetails"]

# PATHS
CONFIG_FILE = "settings.conf"
