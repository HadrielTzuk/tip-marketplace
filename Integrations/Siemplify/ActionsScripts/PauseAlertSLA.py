import time

from TIPCommon import extract_action_param

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import PAUSE_ALERT_SLA_SCRIPT_NAME, PAUSE_ALERT_SLA_MIN_SIEMPLIFY_VERSION_SUPPORTED, SIEMPLIFY_ENDPOINTS
from utils import is_supported_siemplify_version, parse_version_string_to_tuple


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PAUSE_ALERT_SLA_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    pause_sla_reason = extract_action_param(siemplify, param_name="Message", print_value=True, is_mandatory=False, default_value=None)

    status = EXECUTION_STATE_COMPLETED
    result_value = False

    current_version = siemplify.get_system_version()
    siemplify.LOGGER.info(u"Siemplify Platform version is {}".format(current_version))

    if is_supported_siemplify_version(parse_version_string_to_tuple(current_version),
                                      parse_version_string_to_tuple(PAUSE_ALERT_SLA_MIN_SIEMPLIFY_VERSION_SUPPORTED)):
        try:
            request_dict = {"caseId": siemplify.case_id, "alertIdentifier": siemplify.current_alert.identifier}
            if pause_sla_reason:
                request_dict['message'] = pause_sla_reason

            request_url = u"{0}/{1}".format(siemplify.API_ROOT, SIEMPLIFY_ENDPOINTS['pause_alert_sla'])
            response = siemplify.session.post(request_url, json=request_dict)
            siemplify.validate_siemplify_error(response)

            output_message = u"The alert SLA was paused."
            result_value = True

        except Exception as error:
            output_message = u"Failed to pause alert SLA"
            siemplify.LOGGER.error(output_message)
            siemplify.LOGGER.exception(error)
            status = EXECUTION_STATE_FAILED
    else:
        siemplify.LOGGER.info(
            u"Pause Alert SLA is not available for Siemplify versions lower than {}".format(
                PAUSE_ALERT_SLA_MIN_SIEMPLIFY_VERSION_SUPPORTED))
        output_message = u"Pause Alert SLA is not available for Siemplify versions lower than {}".format(
            PAUSE_ALERT_SLA_MIN_SIEMPLIFY_VERSION_SUPPORTED)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info('\n  status: {}\n  result_value: {}\n  output_message: {}'
                          .format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
