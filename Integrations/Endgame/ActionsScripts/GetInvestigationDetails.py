from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, flat_dict_to_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from EndgameManager import EndgameManager
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

INTEGRATION_NAME = u"Endgame"
SCRIPT_NAME = u"Get Investigation Details"


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

    investigation_id = extract_action_param(siemplify, param_name=u"Investigation ID", is_mandatory=True,
                                            input_type=unicode,
                                            print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    json_results = {}
    output_message = u""
    result_value = u"true"
    status = EXECUTION_STATE_COMPLETED

    try:
        endgame_manager = EndgameManager(api_root, username, password, verify_ssl)
        investigation = endgame_manager.get_investigation(
            investigation_id
        )

        siemplify.result.add_data_table(
            u"Endgame Investigation List", flat_dict_to_csv(investigation.as_detailed_csv())
        )
        json_results = investigation.raw_data
        output_message = u'Successfully returned Endgame Investigation {0} details'.format(investigation_id)

    except Exception as e:
        siemplify.LOGGER.error(u"Failed to get details about Endgame Investigation! Error is {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Failed to get details about Endgame Investigation! Error is {}".format(e)

    finally:
        try:
            endgame_manager.logout()
        except Exception as e:
            siemplify.LOGGER.error(u"Logging out failed. Error: {}".format(e))
            siemplify.LOGGER.exception(e)

    siemplify.result.add_result_json(json_results)
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
