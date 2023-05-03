from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from UrlScanManager import UrlScanManager
from constants import INTEGRATION_NAME, GET_SCAN_FULL_DETAILS_SCRIPT_NAME, WEB_REPORT_LINK_TITLE, DOM_TREE_LINK_TITLE, \
    ATTACHMENT_TITLE, ATTACHMENT_FILE_NAME
from UtilsManager import get_screenshot_content_base64


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_SCAN_FULL_DETAILS_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    # INIT INTEGRATION CONFIGURATIONS:
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Key')
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             input_type=bool, print_value=True)

    scan_ids_string = extract_action_param(siemplify, param_name='Scan ID', print_value=True, default_value=False,
                                           is_mandatory=True)
    scan_ids = [scan_id.strip() for scan_id in scan_ids_string.split(',') if scan_id.strip()]
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    scan_result = []
    failed_ids = []
    output_message = ''

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = UrlScanManager(api_key=api_key, verify_ssl=verify_ssl, force_check_connectivity=True)

        for scan_id in scan_ids:
            try:
                scan_result.append(manager.get_scan_report_by_id(scan_id))
            except Exception as err:
                failed_ids.append(scan_id)
                siemplify.LOGGER.error("Action wasn’t able to fetch results for the following scan: {}".format(scan_id))
                siemplify.LOGGER.exception(err)

        for index in range(len(scan_result)):
            details = scan_result[index]
            siemplify.result.add_link(WEB_REPORT_LINK_TITLE.format(INTEGRATION_NAME, details.uuid), details.report_url)
            siemplify.result.add_link(DOM_TREE_LINK_TITLE.format(INTEGRATION_NAME, details.uuid), details.dom_url)
            try:
                screenshot_content = manager.get_screenshot_content(url=details.screenshot_url)
                base64_screenshot = get_screenshot_content_base64(screenshot_content)
                siemplify.result.add_attachment(title=ATTACHMENT_TITLE.format(index + 1),
                                                filename=ATTACHMENT_FILE_NAME.format(details.uuid),
                                                file_contents=base64_screenshot.decode())
            except Exception as e:
                siemplify.LOGGER.error(e)
                siemplify.LOGGER.exception(e)

        if scan_result:
            output_message += 'Successfully fetched results for the following scans: {}\n'.format(
                ', '.join([details.uuid for details in scan_result]))
            siemplify.result.add_result_json([result.to_json() for result in scan_result])

        if failed_ids:
            output_message += 'Action wasn’t able to fetch results for the following scans: {}' \
                .format(', '.join([failed_id for failed_id in failed_ids]))

        if not scan_result:
            result_value = False
            output_message = 'Action wasn’t able to fetch results. The provided scan ids are not available using {}'\
                .format(INTEGRATION_NAME)

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(GET_SCAN_FULL_DETAILS_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
