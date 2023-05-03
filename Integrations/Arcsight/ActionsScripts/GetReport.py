import base64
import json
from ArcsightManager import ArcsightManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param, dict_to_flat, construct_csv
from constants import GET_REPORT_ACTION_NAME, INTEGRATION_NAME, CSV


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_REPORT_ACTION_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    ca_certificate_file = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                      param_name="CA Certificate File")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)

    report_uri = extract_action_param(siemplify, param_name="Report Full Path (URI)", print_value=True,
                                      is_mandatory=True)
    dynamic_parameters = {}

    for param_name, param_value in siemplify.parameters.items():
        if "Field" in param_name and param_value:
            field_name, field_value = param_value.split("=", 1)
            dynamic_parameters[field_name] = field_value

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    json_report = []
    status = EXECUTION_STATE_COMPLETED
    report_name = report_uri.rsplit("/", 1)[-1]

    try:
        arcsight_manager = ArcsightManager(server_ip=api_root, username=username, password=password,
                                           verify_ssl=verify_ssl,
                                           ca_certificate_file=ca_certificate_file)
        arcsight_manager.login()
        # Get Report model
        report = arcsight_manager.get_report_info_by_uri(report_uri)
        # Get link for download report
        report_download_link = arcsight_manager.get_report_download_token(report.report_id, dynamic_parameters)
        report_content = arcsight_manager.download_report(report_download_link)

        if report.report_format == CSV:
            json_report = report_content.to_json(transform_data=True)
            siemplify.result.add_data_table(report_name, construct_csv(report_content.to_csv()))
            siemplify.result.add_result_json(json_report)

        siemplify.result.add_attachment("{} - Report".format(report_name),
                                        "report.{}".format(report.report_format),
                                        base64.b64encode(report_content.raw_data).decode())
        output_message = "Report was downloaded."
        arcsight_manager.logout()

    except Exception as e:
        output_message = "Error executing action {}. Reason: {}".format(GET_REPORT_ACTION_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  output_message: {}".format(status, output_message))
    siemplify.end(output_message, json.dumps(json_report), status)


if __name__ == '__main__':
    main()
