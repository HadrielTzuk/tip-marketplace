from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from SiemplifyDataModel import InsightSeverity, InsightType
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from EndgameManager import EndgameManager
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

INTEGRATION_NAME = u"Endgame"
SCRIPT_NAME = u"Remove IP Subnet From Host Isolation Config"


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

    ip_subnet = extract_action_param(siemplify, param_name=u"IP Subnet", is_mandatory=True,
                                            input_type=unicode,
                                            print_value=True)
    is_insight = extract_action_param(siemplify, param_name=u"Create Insight", is_mandatory=True,
                                     input_type=bool,
                                     print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    output_message = u""
    result_value = u"true"
    status = EXECUTION_STATE_COMPLETED

    try:
        endgame_manager = EndgameManager(api_root, username, password, verify_ssl)
        endgame_manager.remove_ip_subnet_from_isolation_config(
            subnet=ip_subnet
        )

        if is_insight:
            siemplify.create_case_insight(triggered_by=INTEGRATION_NAME,
                                          title=ip_subnet,
                                          content=u"IP Subnet {0} was removed from the Host Isolation Config".format(ip_subnet),
                                          entity_identifier="",
                                          severity=InsightSeverity.INFO,
                                          insight_type=InsightType.General)

        output_message = u'Successfully removed IP subnet from Endgame Host Isolation Config'

    except Exception as e:
        siemplify.LOGGER.error(u"Failed to remove IP subnet from Endgame Host Isolation Config Error is {0}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Failed to remove IP subnet from Endgame Host Isolation Config Error is {0}".format(e)

    finally:
        try:
            endgame_manager.logout()
        except Exception as e:
            siemplify.LOGGER.error(u"Logging out failed. Error: {}".format(e))
            siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
