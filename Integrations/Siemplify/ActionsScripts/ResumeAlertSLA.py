import time

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import RESUME_ALERT_SLA_SCRIPT_NAME, RESUME_ALERT_SLA_MIN_SIEMPLIFY_VERSION_SUPPORTED, SIEMPLIFY_ENDPOINTS
from utils import is_supported_siemplify_version, parse_version_string_to_tuple


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = RESUME_ALERT_SLA_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = False

    current_version = siemplify.get_system_version()
    siemplify.LOGGER.info(u"Siemplify Platform version is {}".format(current_version))

    if is_supported_siemplify_version(parse_version_string_to_tuple(current_version),
                                      parse_version_string_to_tuple(RESUME_ALERT_SLA_MIN_SIEMPLIFY_VERSION_SUPPORTED)):
        try:
            request_dict = {"caseId": siemplify.case_id, "alertIdentifier": siemplify.current_alert.identifier}

            request_url = u"{0}/{1}".format(siemplify.API_ROOT, SIEMPLIFY_ENDPOINTS['resume_alert_sla'])
            response = siemplify.session.post(request_url, json=request_dict)
            siemplify.validate_siemplify_error(response)

            output_message = u"The alert SLA was resumed."
            result_value = True
        except Exception as error:
            output_message = u"Failed to resume alert SLA"
            siemplify.LOGGER.error(output_message)
            siemplify.LOGGER.exception(error)
            status = EXECUTION_STATE_FAILED

    else:
        siemplify.LOGGER.info(
            u"Resume Alert SLA is not available for Siemplify versions lower than {}".format(
                RESUME_ALERT_SLA_MIN_SIEMPLIFY_VERSION_SUPPORTED))
        output_message = u"Resume Alert SLA is not available for Siemplify versions lower than {}".format(
            RESUME_ALERT_SLA_MIN_SIEMPLIFY_VERSION_SUPPORTED)

    siemplify.LOGGER.info(u'----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(u'\n  status: {}\n  result_value: {}\n  output_message: {}'
                          .format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
