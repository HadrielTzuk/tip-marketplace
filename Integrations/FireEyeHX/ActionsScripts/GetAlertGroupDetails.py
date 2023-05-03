from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, flat_dict_to_csv, construct_csv
from FireEyeHXManager import FireEyeHXManager, FireEyeHXNotFoundError
from SiemplifyUtils import output_handler
from UtilsManager import convert_comma_separated_to_list

INTEGRATION_NAME = u"FireEyeHX"
INTEGRATION_DISPLAY_NAME = u'FireEye HX'
SCRIPT_NAME = u"Get Alert Group Details"


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

    alert_group_id = extract_action_param(siemplify, param_name=u"Alert Group ID", is_mandatory=True,
                                          input_type=unicode, print_value=True)
    alert_group_ids = list(set(convert_comma_separated_to_list(alert_group_id)))

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    
    output_message = ""
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    successful_groups = []
    failed_groups = []
    json_results = []
    all_alert_details = []
    
    try:
        hx_manager = FireEyeHXManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl)

        for group_id in alert_group_ids:
            try:
                alert_details = hx_manager.get_alert_group_details(alert_group_id=group_id)

                if alert_details:
                    successful_groups.append(group_id)
                    all_alert_details.append(alert_details.to_table())
                    json_results.append(alert_details.raw_data)
                else:
                    failed_groups.append(group_id)

            except Exception as e:
                failed_groups.append(group_id)
                siemplify.LOGGER.error(u"Couldn't fetch details for the provided alert group ID {}. "
                                       u"Please check the provided ID and try again.".format(group_id))
                siemplify.LOGGER.exception(e)

        if successful_groups:
            siemplify.result.add_result_json(json_results)
            siemplify.result.add_data_table("Alert Group Details", construct_csv(all_alert_details))
            output_message += "Successfully retrieved details about the following alert groups in {}: \n{}" \
                .format(INTEGRATION_DISPLAY_NAME, "\n".join([group_id for group_id in successful_groups]))

        if failed_groups:
            output_message += "\nAction wasn't able to retrieve details about the following alert groups in {}: " \
                              "\n{}".format(INTEGRATION_DISPLAY_NAME, "\n".join([group_id for group_id in failed_groups]
                                                                                ))

        if not successful_groups:
            result_value = False
            output_message = "None of the provided Alert Groups were found in {}".format(INTEGRATION_DISPLAY_NAME)

    except Exception as e:
        siemplify.LOGGER.error(u"Failed to execute {} action, error is {}.".format(SCRIPT_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = u"Failed to execute {} action, error is {}.".format(SCRIPT_NAME, e)
    
    finally:
        try:
            hx_manager.logout()
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
