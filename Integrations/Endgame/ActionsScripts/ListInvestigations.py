from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, utc_now, convert_datetime_to_unix_time
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from EndgameManager import EndgameManager
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
import datetime

INTEGRATION_NAME = u"Endgame"
SCRIPT_NAME = u"List Investigations"
DEFAULT_OS = u"Solaris, Windows, MacOs, Linux"


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

    os_filters = extract_action_param(siemplify, param_name=u"OS", is_mandatory=False, input_type=unicode,
                                      print_value=True, default_value=DEFAULT_OS)
    max_hours_backwards = extract_action_param(siemplify, param_name=u"Fetch investigations for the last X hours",
                                               is_mandatory=False, input_type=int,
                                               print_value=True)
    results_limit = extract_action_param(siemplify, param_name=u"Max Investigation to Return",
                                               is_mandatory=False, input_type=int,
                                               print_value=True)

    os_filters = [os_filter.strip() for os_filter in os_filters.split(u",")] if os_filters else []
    created_from = None

    if max_hours_backwards:
        created_from = convert_datetime_to_unix_time(utc_now() - datetime.timedelta(hours=max_hours_backwards))
        siemplify.LOGGER.info(u"Setting create_from filter to {}".format(created_from))

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    json_results = {}
    output_message = u""
    result_value = u"true"
    status = EXECUTION_STATE_COMPLETED

    try:
        endgame_manager = EndgameManager(api_root, username, password, verify_ssl)
        investigations = endgame_manager.get_investigations(
            os_filters=os_filters,
            created_from=created_from,
            limit=results_limit
        )

        if investigations:
            siemplify.result.add_data_table(u"Endgame Investigation List", construct_csv([investigation.as_csv() for investigation in investigations]))
            json_results = [investigation.raw_data for investigation in investigations]
            output_message = u'Successfully listed Endgame Investigations.'
        else:
            output_message = u'There are no investigations right now'

    except Exception as e:
        siemplify.LOGGER.error(u"Failed to get Endgame Investigations! Error is {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Failed to get Endgame Investigations! Error is {}".format(e)

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
