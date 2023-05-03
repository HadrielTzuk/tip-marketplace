import os
import argparse
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--path', help='folder')
    args = parser.parse_args()
    Json_Integration = {
        "RSAArcher": "SyncSecurityIncidents",
        "NessusScanner": "LaunchScanAndGetAReport",
        "FreshworksFreshservice": "SyncTicketsClosure",
        "Siemplify": ["Measurement Monitor", "Cases Collector", "Actions Monitor"]
    }
    for item in Json_Integration:
        connector_to_remove = Json_Integration.get(item)
        if type(connector_to_remove) is list:
            for connector in connector_to_remove:
                integration = item
                file_to_remove = str(args.path) + '/Integrations' + '/' + str(integration) + "/Jobs" + '/' + str(connector) + '.jobdef'
                print(file_to_remove)
                file_to_remove_script = str(args.path) + '/Integrations' + '/' + str(integration) + "/JobsScrips" + '/' + str(connector) + '.py'
                print(file_to_remove_script)
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
            integration = item
            file_to_remove = str(args.path) + '/Integrations' + '/' + str(integration) + "/Jobs" + '/' + str(connector_to_remove) + '.jobdef'
            print(file_to_remove)
            file_to_remove_script = str(args.path) + '/Integrations' + '/' + str(integration) + "/JobsScrips" + '/' + str(connector_to_remove) + '.py'
            print(file_to_remove_script)
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
