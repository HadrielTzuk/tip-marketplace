from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from FalconSandboxManager import FalconSandboxManager, FalconSandboxInvalidCredsError
from TIPCommon import extract_configuration_param, extract_action_param

SCRIPT_NAME = u'Submit File'
INTEGRATION_NAME = u'FalconSandbox'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Root",
                                           is_mandatory=True, input_type=unicode)
    key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Key",
                                           is_mandatory=True, input_type=unicode)

    #  INIT ACTION PARAMETERS:
    file_paths = extract_action_param(siemplify, param_name=u'File Path', print_value=True, is_mandatory=True)
    environment_name = extract_action_param(siemplify, param_name=u'Environment', input_type=unicode, print_value=True,
                                            default_value=u'Linux (Ubuntu 16.04, 64 bit)')

    file_paths = [file_path.strip() for file_path in file_paths.split(u",")]
    environment_id = FalconSandboxManager.get_environment_id_by_name(environment_name)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    successful_paths = []
    json_results = {}
    failed_paths = []
    status = EXECUTION_STATE_COMPLETED
    result_value = u"false"

    try:
        manager = FalconSandboxManager(server_address, key)

        for file_path in file_paths:
            try:
                siemplify.LOGGER.info(u"Submitting {} for analysis with environment {}".format(file_path, environment_name))
                job_id, sha256 = manager.submit_file(file_path, environment_id)
                siemplify.LOGGER.info(u"Successfully submitted {}. Job id: {}".format(file_path, job_id))
                successful_paths.append(file_path)

                json_results[file_path] = {
                    u'job_id': job_id,
                    u'sha256': sha256
                }

            except FalconSandboxInvalidCredsError as e:
                raise

            except Exception as e:
                failed_paths.append(file_path)
                siemplify.LOGGER.error(u"An error occurred on file {}".format(file_path))
                siemplify.LOGGER.exception(e)

        if successful_paths:
            output_message = u"Successfully submit the following files:\n   {}\n\n".format(
                u"\n   ".join([file_path for file_path in successful_paths])
            )
            result_value = u"true"

        else:
            output_message = u"No files were submitted for analysis.\n\n"

        if failed_paths:
            output_message += u"An error occurred on the following files:\n   {}\n\nPlease check logs for more information.".format(
                u"\n   ".join([file_path for file_path in failed_paths])
            )

    except Exception as e:
        siemplify.LOGGER.error(u"General error occurred while running action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"An error occurred while running action. Error: {}".format(e)

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == u"__main__":
    main()
