from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from QualysVMManager import QualysVMManager
from QualysVMExceptions import QualysVMManagerError
from constants import INTEGRATION_NAME, FETCH_REPORT_SCRIPT_NAME, FINISH_STATE, ERROR_STATES
import base64
import time


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = FETCH_REPORT_SCRIPT_NAME
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
    report_id = extract_action_param(siemplify, param_name="Report ID", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result = True
    status = EXECUTION_STATE_COMPLETED
    json_results = {}

    try:
        qualys_manager = QualysVMManager(api_root, username, password, verify_ssl)
        
        while True:
            try:
                # Try to fetch the report
                report = qualys_manager.get_report(report_id)
                
                if report.get("STATUS", {}).get("STATE") == FINISH_STATE:
                    json_results = report
                    break
                
                if report.get("STATUS", {}).get("STATE") in ERROR_STATES:
                    raise QualysVMManagerError(f"Report {report_id} ended with error. Couldn't download the report.")
                      
            except QualysVMManagerError as e:
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

        if json_results:
            siemplify.result.add_result_json(json_results)

        output_message = "Report {} was downloaded as attachment.".format(report_id)

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {FETCH_REPORT_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{FETCH_REPORT_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
