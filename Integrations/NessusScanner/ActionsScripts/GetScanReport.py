from SiemplifyUtils import output_handler
# Imports
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS
from NessusScannerManager import NessusScanner
import base64

# Consts:
SCAN_STATUS = 'completed'


@output_handler
def main():
    siemplify = SiemplifyAction()

    # Configuration.
    conf = siemplify.get_configuration('NessusScanner')
    access_key = conf['Access Key']
    secret_key = conf['Secret Key']
    server_address = conf['Api Root']
    nessus_client = NessusScanner(access_key, secret_key, server_address)

    # Parameters
    scan_name = siemplify.parameters['Scan Name']

    scan_details = nessus_client.get_scan_details(scan_name)
    json_results = {}
    if scan_details:
        json_results = scan_details

    siemplify.result.add_result_json = json_results

    # Verify scan has been completed
    if scan_details['info']['status'] == SCAN_STATUS:
        report = nessus_client.download_scan(scan_name)
        if report:
            siemplify.result.add_attachment("Nessus Report", "ScanReport.html", base64.b64encode(report))
            output_message = "Scan has been completed, Report is attached."
            result_value = 'true'
            siemplify.end(output_message, result_value, EXECUTION_STATE_COMPLETED)
        else:
            output_message = "Failed to download '{0}' scan".format(scan_name)
            result_value = 'false'
            siemplify.end(output_message, result_value, EXECUTION_STATE_COMPLETED)

    else:
        output_message = "Scan has not been completed yet, scan status is: {0}".format(scan_details['info']['status'])
        result_value = 'false'
        siemplify.end(output_message, result_value, EXECUTION_STATE_INPROGRESS)


if __name__ == '__main__':
    main()
