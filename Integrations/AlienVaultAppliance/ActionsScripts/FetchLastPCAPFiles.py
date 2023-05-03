from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import construct_csv
from AlienVaultManager import AlienVaultManager, AlienVaultManagerError
import base64
import json

PROVIDER = 'AlienVaultAppliance'
TABLE_NAME = 'PCAP Records'


@output_handler
def main():
    siemplify = SiemplifyAction()
    configurations = siemplify.get_configuration(PROVIDER)
    server_address = configurations['Api Root']
    username = configurations['Username']
    password = configurations['Password']

    result_value = False
    
    # Parameters
    number_of_files_to_fetch = int(siemplify.parameters.get('Number Of Files To Fetch', 1))

    alienvault_manager = AlienVaultManager(server_address, username, password)

    # Get pcap files records.
    pcap_records = alienvault_manager.get_last_pcap_files()

    final_pcap_records = pcap_records[:number_of_files_to_fetch]

    for pcap_record in final_pcap_records:
        # Fetch file content.
        file_content = alienvault_manager.download_pcap_file(pcap_record.get('scan_name'),
                                                             pcap_record.get('sensor_ip'))
        siemplify.result.add_attachment(pcap_record.get('scan_name'),
                                        pcap_record.get('scan_name'),
                                        base64.b64encode(file_content))

    if pcap_records:
        siemplify.result.add_data_table(TABLE_NAME, construct_csv(pcap_records[:number_of_files_to_fetch]))
        result_value = True
        output_message = 'Found {0} PCAP files.'.format(len(pcap_records[:number_of_files_to_fetch]))
    else:
        output_message = 'No PCAP files were found.'

    siemplify.result.add_result_json(final_pcap_records)
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
  main()





