from SiemplifyUtils import output_handler
# Imports
from SiemplifyAction import SiemplifyAction
from NessusScannerManager import NessusScanner


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

    # Get scan id base on scan name
    scan_details = nessus_client.get_scan_details(scan_name)
    scan_id = scan_details['info']['object_id']

    # Launch scan
    scan = nessus_client.launch_scan_by_id(scan_id)
    scan_details = nessus_client.get_scan_details(scan_name)
    targets = scan_details['info']['targets']

    if scan:
        output_message = 'Scan - {0}, initiated for: \n{1}'.format(scan_name, targets)
        result_value = 'true'
    else:
        output_message = 'Failed to launch scan {0}.'.format(scan_name)
        result_value = 'false'

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()