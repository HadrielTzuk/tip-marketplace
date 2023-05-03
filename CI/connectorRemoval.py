import os
import argparse
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--path', help='folder')
    args = parser.parse_args()
    Json_Integration = {
        "CaServiceDesk": "CA Service Desk Connector",
        "Endgame": "EndgameConnector",
        "FireEyeETP": "EmailAlertsConnector",
        "CBResponse": "CBResponseConnector",
        "Email": ["EmailConnector", "EmailEMLConnector"],
        "FortinetFortiSIEM": "FortiSIEMIncidentsConnector",
        "PaloAltoPanorama": "Palo Alto Panorama - Threat Log Connector",
        "AlienVaultAnywhere": "AlienVaultConnector",
        "Arcsight": "Arcsight ESM Connector",
        "Armis": "ArmisAlertsConnector",
        "GoogleChronicle": "GoogleChronicleIOCConnector",
        "Attivo": "EventsConnector",
        "AWSSecurityHub": "SecurityHubFindingsConnector",
        "BlueLiv": "ThreatsConnector",
        "BMCHelixRemedyForce": "IncidentsConnector",
        "CheckPointCloudGuard": "CheckPointCloudGuardAlertsConnector",
        "HarmonyMobile": "HarmonyMobileAlertsConnector",
        "Humio": "HumioEventsConnector",
        "CofenseTriage": "CofenseTriageReportsConnector",
        "CSV": "CSVConnector",
        "Cybereason": "MalopsInboxConnector",
        "Cyberint": "AlertsConnector",
        "Darktrace": "DarktraceModelBreachesConnector",
        "DigitalShadows": "IncidentConnector",
        "Vectra": "DetectionsConnector",
        "TenableSecurityCenter": "TenableSecurityCenterConnector",
        "TenableIO": "VulnerabilitiesConnector",
        "SymantecICDX": "SymantecICDXQueryConnector",
        "Sumologic": "SumologicConnector",
        "StellarCyberStarlight": "SecurityEventsConnector",
        "Site24x7": "AlertsLogConnector",
        "SiemplifyThreatFuse": "ThreatFuseObservablesConnector",
        "SentinelOneV2": "ThreatsConnector",
        "RSANetWitness": "RSANetWitnessQueryConnector",
        "RSAArcher": "SecurityIncidentsConnector",
        "Rapid7InsightVm": "VulnerabilitiesConnector",
        "QualysVM": "DetectionsConnector",
        "QualysEDR": "QualysEDREventsConnector",
        "QRadar": ["MonitorEvents", "QRadar Offenses Connector", "QRadar New Correlations Events Connector", "QRadar Correlations Events Connector", "QRadar Correlation Events Connector V2"],
        "PaloAltoCortexXDR": "XDRConnector",
        "Outpost24": "OutscanFindingsConnector",
        "ObserveIT": "ObserveIT - Alerts Connector",
        "Mimecast": "MessageTrackingConnector",
        "McAfeeESM": "McAfee ESM Connector",
        "McAfeeMvisionEPOV2": "McAfeeMvisionEPOV2EventsConnector",
        "Fortigate": "ThreatLogsConnector",
        "FireEyeETP": "EmailAlertsConnector",
        "FreshworksFreshservice": "FreshserviceTicketsConnector"
    }
    for item in Json_Integration:
        connector_to_remove = Json_Integration.get(item)
        integration = item
        if type(connector_to_remove) is list:
            for connector in connector_to_remove:
                file_to_remove = str(args.path) + '/Integrations' + '/' + str(integration) + "/Connectors" + '/' + str(connector) + '.connectordef'
                file_to_remove_script = str(args.path) + '/Integrations' + '/' + str(integration) + "/ConnectorsScripts" + '/' + str(connector) + '.py'
                try:
                    os.remove(file_to_remove)
                except OSError as err:
                    print("OS error: {0}".format(err))
                    pass
                try:
                    os.remove(file_to_remove_script)
                except OSError as err:
                    print("OS error: {0}".format(err))
                    pass
        else:
            file_to_remove = str(args.path) + '/Integrations' + '/' + str(integration) + "/Connectors" + '/' + str(connector_to_remove) + '.connectordef'
            file_to_remove_script = str(args.path) + '/Integrations' + '/' + str(integration) + "/ConnectorsScripts" + '/' + str(connector_to_remove) + '.py'
            try:
                os.remove(file_to_remove)
            except OSError as err:
                print("OS error: {0}".format(err))
                pass
            try:
                os.remove(file_to_remove_script)
            except OSError as err:
                print("OS error: {0}".format(err))
                pass
if __name__ == "__main__":
    main()
