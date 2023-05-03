from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from Office365CloudAppSecurityManager import Office365CloudAppSecurityManager, Office365CloudAppSecurityConfigurationError
from Office365CloudAppSecurityCommon import Office365CloudAppSecurityCommon
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SiemplifyDataModel import EntityTypes
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

# =====================================
#             CONSTANTS               #
# =====================================
INTEGRATION_NAME = "Office365CloudAppSecurity"
SCRIPT_NAME = "Office365CloudAppSecurity - Get IP Related Activities"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    result_value = "true"
    output_message = ""
    json_results = {}

    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="portal URL", input_type=str)

    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API token", input_type=str)

    # INIT ACTION PARAMETERS:
    activity_display_limit = extract_action_param(siemplify, param_name="Activity Display Limit", is_mandatory=False, print_value=True, input_type=int)
    product_name = extract_action_param(siemplify, param_name="Product name", is_mandatory=False, print_value=True, input_type=str)
    time_frame = extract_action_param(siemplify, param_name="Time Frame", is_mandatory=True, print_value=True, input_type=int)

    cloud_app_manager = Office365CloudAppSecurityManager(api_root=api_root, api_token=api_token)
    cloud_app_common = Office365CloudAppSecurityCommon(siemplify.LOGGER)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    try:
        status = EXECUTION_STATE_COMPLETED
        failed_entities = []
        successfull_entities = []
        no_activities = []

        for entity in siemplify.target_entities:
            if entity.entity_type == EntityTypes.ADDRESS:
                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))
                if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                    siemplify.LOGGER.error("Timed out. execution deadline ({}) has passed".format(
                        convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                    status = EXECUTION_STATE_TIMEDOUT
                    break
                try:
                    activities = cloud_app_manager.get_ip_related_activities(entity.identifier, product_name,
                                                                             time_frame, activity_display_limit)

                    if not activities:
                        no_activities.append(entity.identifier)
                        siemplify.LOGGER.error("No alert related activities were found: {}".format(entity.identifier))
                    else:
                        json_results[entity.identifier] = [activity.to_json() for activity in activities]

                        activity_table = construct_csv([activity.to_table_data() for activity in activities])
                        siemplify.result.add_data_table(title="{} Related Activity Table ".format(entity.identifier),
                                                        data_table=activity_table)

                        output_message += "Alert related activities for the following ip were fetched:{}. \n".format(
                            entity.identifier)

                    successfull_entities.append(entity)
                    siemplify.LOGGER.info("Finished processing entity {0}".format(entity.identifier))
                    pass
                
                except Office365CloudAppSecurityConfigurationError as e:
                    raise

                except Exception as e:
                    failed_entities.append(entity)
                    siemplify.LOGGER.error("An error occurred on entity {0}".format(entity.identifier))
                    siemplify.LOGGER.exception(e)
            else:
                siemplify.LOGGER.info("The entity {} is not a type of ADDRESS, skipping...".format(entity.identifier))

        if no_activities:
            output_message += "\n No activities related to these IP addresses: {} were found.\n".format(", ".join([entity for entity in no_activities]))

        if not successfull_entities:
            siemplify.LOGGER.info("\n No entities where processed.")
            output_message = "No entities where processed."

        if failed_entities:
            siemplify.LOGGER.info("\n Failed processing entities:\n   {}".format(
                "\n".join([entity.identifier for entity in failed_entities])))


    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = 'Error executing action \"Get IP Related Activities\". Reason: {}'.format(e)

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        "\n  status: {}\n  result_value: {}\n  output_message: {}".format(status,result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
