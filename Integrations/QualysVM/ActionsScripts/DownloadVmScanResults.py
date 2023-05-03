from SiemplifyUtils import output_handler,unix_now, convert_unixtime_to_datetime
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, flat_dict_to_csv, construct_csv, dict_to_flat
from QualysVMManager import QualysVMManager
from constants import INTEGRATION_NAME, DOWNLOAD_VM_SCAN_RESULTS_SCRIPT_NAME, SCAN_TEMPLATE, FINISH_STATE, ERROR_STATES 
import base64
import time
import json
from QualysVMExceptions import QualysReportFailed

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = DOWNLOAD_VM_SCAN_RESULTS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True, print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    # Action parameters
    scan_id = extract_action_param(siemplify, param_name="Scan ID", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result = True
    status = EXECUTION_STATE_COMPLETED
    json_results = {}

    try:
        qualys_manager = QualysVMManager(api_root, username, password, verify_ssl)
        results = qualys_manager.get_vm_scan_results(scan_id)

        report_id = qualys_manager.launch_scan_report(
            report_title="Scan {} Report".format(scan_id),
            template_id=qualys_manager.get_template_id_by_name(SCAN_TEMPLATE),
            output_format="pdf",
            report_refs=[scan_id],
        )
        
        while True:
            
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error("Timed out. execution deadline ({}) has passed".format(
                        convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms))
                    )
            try:
                # Try to fetch the report
                report = qualys_manager.get_report(report_id)
                
                if report.get("STATUS", {}).get("STATE") == FINISH_STATE:
                    json_results = report
                    break
                
                if report.get("STATUS", {}).get("STATE") in ERROR_STATES:
                    raise QualysReportFailed(f"Report {report_id} ended with error. Couldn't download the report.")
                      
            except QualysReportFailed as e:
                raise

            except Exception:
                # Report was not yet initiated and created in the DB - try again
                time.sleep(1)
                continue
            
        report_data = qualys_manager.fetch_report(report_id=report_id)

        siemplify.result.add_attachment(
            title="Report {}".format(report_id),
            filename=report_data["name"],
            file_contents=base64.b64encode(report_data["content"]).decode()
        )

        if results:
            results_summary = results[1]
            actual_results = results[2:]
            siemplify.result.add_data_table(
                "Report Summary",
                flat_dict_to_csv(dict_to_flat(results_summary))
            )
            siemplify.result.add_data_table(
                "Scan Results",
                construct_csv(actual_results)
            )
            json_results = json.dumps(results)

        # add json result
        if json_results:
            siemplify.result.add_result_json(json_results)

        output_message = "Scan results fetched for scan: {}".format(scan_id)

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {DOWNLOAD_VM_SCAN_RESULTS_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{DOWNLOAD_VM_SCAN_RESULTS_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
