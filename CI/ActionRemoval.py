import os
import argparse
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--path', help='folder')
    args = parser.parse_args()
    Json_Integration = {
    "EmailV2": ["SendEmail", "SaveEmailAttachmentsToCase", "WaitForEmailFromUser", "DownloadEmailAttachments", "ForwardEmail", "SendThreadReply"],
    "Endgame": "DownloadFile",
    "FireEyeAX": "SubmitFile",
    "FireEyeCM": ["AddIOCFeed", "AddRuleToCustomRulesFile", "DownloadCustomRulesFile", "DownloadAlertArtifacts", "DownloadQuarantinedEmail"],
    "FireEyeEX": ["DownloadQuarantinedEmail", "DownloadAlertArtifacts"],
    "FireEyeNX": "DownloadAlertArtifacts",
    "Intezer": "SubmitFile",
    "Intsights": "DownloadAlertCSV",
    "Jira": ["DownloadAttachments", "UploadAttachment"],
    "JoeSandbox": "DetonateFile",
    "McAfeeATD": "SubmitFile",
    "VirusTotalV3": ["SubmitFile", "DownloadFile"],
    "VirusTotal": "UploadAndScanFile",
    "AnyRun": "AnalyzeFile",
    "CBLiveResponse": ["DownloadFile", "PutFile"],
    "GoogleCloudStorage": "DownloadObjectFromBucket",
    "CBResponse": "DownloadBinary",
    "CheckPointFirewall": "DownloadLogAttachment",
    "CheckPointSandBlast": "UploadFile",
    "CiscoThreatGrid": "UploadSample",
    "CofenseTriage": ["DownloadReportPreview", "DownloadReportEmail"],
    "CrowdStrikeFalcon": "DownloadFilesFromHosts",
    "Lastline": "SubmitFile",
    "Email": "DownloadEmailAttachments",
    "TrendMicroApexCentral": "CreateFileUDSO",
    "Tanium": "DownloadFile",
    "Slack": "UploadFile",
    "SiemplifyUtilities": "EmailParser",
    "ServiceNow": ["DownloadAttachments", "UpdateTheTIDatabaseOfNetWitnessRawInput"],
    "RSAArcher": ["CreateIncident", "UpdateIncident"],
    "ReversinglabsA1000": "UploadFile",
    "RemoteAgentUtilities": ["SerializeAFile", "DeserializeAFile"],
    "PaloAltoPanorama": ["EditBlockedApplications", "BlockIpsInPolicy", "AddIpsToGroup", "RemoveIpFromGroup", "UnblockIpsInPolicy"],
    "PaloAltoNGFW": ["EditBlockedApplications", "BlockIpsInPolicy", "BlockURLs", "UnblockIpsInPolicy", "AddIpsToGroup", "RemoveIpFromGroup", "UnblockURLs"],
    "LogRhythm": ["AttachFileToCase", "DownloadCaseFiles"],
    "FreshworksFreshservice": ["FreshserviceTicketsConnector", "UpdateTicket", "CreateTicket"],
    "FalconSandbox": ["SubmitFile", "AnalyzeFile"],
    "MalShare": "UploadFile",
    "ExchangeExtensionPack": ["RunComplianceSearch", "FetchComplianceSearchResults", "PurgeComplianceSearchResults"]
    }


    for item in Json_Integration:
        connector_to_remove = Json_Integration.get(item)
        if type(connector_to_remove) is list:
            for connector in connector_to_remove:
                integration = item
                file_to_remove = str(args.path) + '/Integrations' + '/' + str(integration) + "/ActionsDefinitions" + '/' + str(connector) + '.actiondef'
                file_to_remove_action = str(args.path) + '/Integrations' + '/' + str(integration) + "/ActionsDefinitions" + '/' + str(connector) + '.action'
                file_to_remove_script = str(args.path) + '/Integrations' + '/' + str(integration) + "/ActionsScripts" + '/' + str(connector) + '.py'
                try:
                    os.remove(file_to_remove)
                except OSError as err:
                    print("OS error: {0}".format(err))
                    pass
                try:
                    os.remove(file_to_remove_action)
                except OSError as err:
                    print("OS error: {0}".format(err))
                    try:
                        os.remove(file_to_remove_script)
                    except OSError as err:
                        print("OS error: {0}".format(err))
                        pass
                        pass
        else:
            integration = item
            file_to_remove = str(args.path) + '/Integrations' + '/' + str(integration) + "/ActionsDefinitions" + '/' + str(connector_to_remove) + '.actiondef'
            file_to_remove_action = str(args.path) + '/Integrations' + '/' + str(integration) + "/ActionsDefinitions" + '/' + str(connector_to_remove) + '.action'
            file_to_remove_script = str(args.path) + '/Integrations' + '/' + str(integration) + "/ActionsScripts" + '/' + str(connector_to_remove) + '.py'
            try:
                os.remove(file_to_remove)
            except OSError as err:
                print("OS error: {0}".format(err))
                pass
            try:
                os.remove(file_to_remove_script)
            except OSError as err:
                print("OS error: {0}".format(err))
                try: 
                    os.remove(file_to_remove_action)
                except OSError as err:
                    print("OS error: {0}".format(err))
                    pass
                    pass

if __name__ == "__main__":
    main()
