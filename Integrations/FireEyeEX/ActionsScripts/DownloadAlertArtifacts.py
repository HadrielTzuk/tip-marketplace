# coding=utf-8
from SiemplifyUtils import output_handler
from FireEyeEXManager import FireEyeEXManager, FireEyeEXUnsuccessfulOperationError, FireEyeEXDownloadFileError
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
import base64
from urlparse import urljoin

INTEGRATION_NAME = u"FireEyeEX"
SCRIPT_NAME = u"Download Alert Artifacts"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True, input_type=unicode)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                          is_mandatory=True, input_type=unicode)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                         is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    alert_uuid = extract_action_param(siemplify, param_name=u"Alert UUID", is_mandatory=True,
                                    input_type=unicode, print_value=True)
    download_path = extract_action_param(siemplify, param_name=u"Download Path", is_mandatory=False,
                                    input_type=unicode, print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = u"true"

    try:
        ex_manager = FireEyeEXManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl)
        zip_content = ex_manager.download_alert_artifacts(alert_uuid)

        try:
            siemplify.result.add_attachment(u"Alert_Artifacts_{}.zip".format(alert_uuid),
                                            u"Alert_Artifacts_{}.zip".format(alert_uuid),
                                            base64.b64encode(zip_content.content))
            
            absolute_path = urljoin(download_path, u'Alert_Artifacts_{}.zip'.format(alert_uuid))
            
            if ex_manager.save_artifacts_to_file(zip_content, absolute_path):
                siemplify.result.add_result_json({'file_path': absolute_path})
                output_message = u"Successfully downloaded FireEye EX alert artifacts with alert id {}!".format(alert_uuid)
            else:
                output_message = u"Action wasn’t able to download FireEye EX alert artifacts with alert id {}. Reason: File with that path already exists.".format(alert_uuid)
                result_value = u"false"
            
        except FireEyeEXDownloadFileError as e:
            siemplify.LOGGER.error(u"Unable to attach downloaded artifacts. Reason: {}".format(e))
            output_message = u"Unable to attach downloaded artifacts. Reason: {}".format(e)
            result_value = u"false"

        except EnvironmentError:
            # File size is too big
            siemplify.LOGGER.error(u"Unable to attach downloaded artifacts. Reason: artifacts are too large in size.")
            output_message = u"Unable to attach downloaded artifacts. Reason: artifacts are too large in size."
            result_value = u"false"

        ex_manager.logout()

    except Exception as e:
        siemplify.LOGGER.error(u"Error executing action \"Download Alert Artifacts\". Reason: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Error executing action \"Download Alert Artifacts\". Reason: {}".format(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == u"__main__":
    main()
