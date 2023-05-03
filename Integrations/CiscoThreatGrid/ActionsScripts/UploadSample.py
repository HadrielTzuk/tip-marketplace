from SiemplifyUtils import output_handler
from CiscoThreatGridManager import CiscoThreatGridManager, \
    HTML_REPORT_DOWNLOAD_LINK, SCREENSHOT_DOWNLOAD_LINK, \
    PCAP_DOWNLOAD_LINK
from SiemplifyUtils import construct_csv
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
import sys
import base64
import json
from TIPCommon import extract_action_param
from FileManager import FileManager

LINK = "{}/samples/{}"
SCRIPT_NAME = 'CiscoThreatGrid - Upload Sample'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    conf = siemplify.get_configuration('CiscoThreatGrid')
    server_addr = conf['Api Root']
    api_key = conf['Api Key']
    use_ssl = conf['Use SSL'].lower() == 'true'
    cisco_threat_grid = CiscoThreatGridManager(server_addr, api_key, use_ssl)

    file_path = siemplify.parameters['File Path']
    vm = siemplify.parameters.get('Vm')
    playbook = siemplify.parameters.get('Playbook')
    network_exit = siemplify.parameters.get('Network Exit')
    private = siemplify.parameters['Private'].lower() == 'true'

    linux_server_address = extract_action_param(siemplify, param_name="Linux Server Address", print_value=True)
    linux_username = extract_action_param(siemplify, param_name="Linux Username", print_value=True)
    linux_password = extract_action_param(siemplify, param_name="Linux Password")

    try:
        if linux_server_address or linux_username or linux_password:
            if linux_server_address and linux_username and linux_password:
                file_manager = FileManager(linux_server_address, linux_username, linux_password)
                file_content = file_manager.get_remote_unix_file_content(file_path)
            else:
                raise Exception("for remote server connection you need to provide values for all parameters "
                                "\"Linux Server Address\", \"Linux Username\", \"Linux Password\".")
        else:
            file_content = open(file_path, 'rb')

        sample_id = cisco_threat_grid.analyze_sample(file_path, file_content, vm=vm, playbook=playbook, private=private,
                                                     network_exit=network_exit)

        output_massage = "Sample {} was uploaded successfully. Waiting for analysis.".format(sample_id)
        siemplify.LOGGER.info("Sample {} submitted successfully. Waiting for analysis.".format(sample_id))
        result = sample_id
        status = EXECUTION_STATE_INPROGRESS

    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_massage = "Error executing action {}. Reason: {}".format(SCRIPT_NAME, e)

    siemplify.end(output_massage, result, status)


def analyze_async():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    conf = siemplify.get_configuration('CiscoThreatGrid')
    server_addr = conf['Api Root']
    api_key = conf['Api Key']
    use_ssl = conf['Use SSL'].lower() == 'true'
    cisco_threat_grid = CiscoThreatGridManager(server_addr, api_key, use_ssl)

    # Extract web id
    sample_id = siemplify.parameters["additional_data"]

    try:
        if cisco_threat_grid.is_sample_completed(sample_id):
            siemplify.LOGGER.info("Sample {} analysis is complete.".format(sample_id))

            # Add link to html report
            siemplify.result.add_link(
                'Download Analysis HTML Report',
                HTML_REPORT_DOWNLOAD_LINK.format(
                    server_addr,
                    sample_id,
                    api_key
                )
            )

            # Attach link to network pcap
            siemplify.result.add_link(
                'Download Network Pcap',
                PCAP_DOWNLOAD_LINK.format(
                    server_addr, sample_id, api_key)
            )

            # Attach link to screenshot
            siemplify.result.add_link(
                'Download Screenshot',
                SCREENSHOT_DOWNLOAD_LINK.format(
                    server_addr,
                    sample_id,
                    api_key)
            )

            threat = cisco_threat_grid.get_sample_threat(sample_id)
            try:
                threat_table = cisco_threat_grid.create_threat_table(threat)
                if threat_table:
                    csv_output = construct_csv(threat_table)
                    siemplify.result.add_data_table("Threat Report", csv_output)

            except Exception as e:
                # Attachment cannot be larger than 3 MB
                siemplify.LOGGER.error(
                    "Can not add threat table for {}:\n{}.".format(
                        sample_id,
                        str(e)))

            # Add link to the report
            siemplify.result.add_link("Report - {}".format(sample_id),
                                      LINK.format(server_addr, sample_id))

            max_severity = threat.get("max-severity", -1)
            max_confidence = threat.get("max-confidence", -1)
            score = (max_severity * max_confidence) / 100

            output_massage = "Analysis completed. ThreatScore: {}".format(
                score)

            # add json
            siemplify.result.add_result_json(threat)
            siemplify.end(output_massage, score, EXECUTION_STATE_COMPLETED)

        else:
            siemplify.LOGGER.info("Sample {} is pending for analysis.".format(sample_id))
            output_massage = "Waiting for analysis to complete: {}".format(sample_id)
            siemplify.end(output_massage, sample_id, EXECUTION_STATE_INPROGRESS)

    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        output_massage = "Error executing action {}. Reason: {}".format(SCRIPT_NAME, e)
        siemplify.end(output_massage, False, EXECUTION_STATE_FAILED)


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main()
    else:
        analyze_async()
