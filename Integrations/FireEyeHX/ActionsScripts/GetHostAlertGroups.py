from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler, \
    convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from FireEyeHXManager import FireEyeHXManager, FireEyeHXNotFoundError
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv


INTEGRATION_NAME = u"FireEyeHX"
SCRIPT_NAME = u"Get Host Alert Groups"
SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]
ONLY_ACKNOWLEDGED = "Only Acknowledged"
ONLY_UNACKNOWLEDGED = "Only Unacknowledged"


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

    ack_filter = extract_action_param(siemplify, param_name=u"Acknowledgment Filter", is_mandatory=False,
                                      input_type=unicode, print_value=True)
    limit = extract_action_param(siemplify, param_name=u"Max Alert Groups To Return", is_mandatory=False,
                                 input_type=int, print_value=True)

    acknowledgement = True if ack_filter == ONLY_ACKNOWLEDGED else False if ack_filter == ONLY_UNACKNOWLEDGED else None

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    failed_entities = []
    json_results = {}
    output_message = u""
    result_value = True

    try:
        if limit < 1:
            raise Exception("\"Max Alert Groups To Return\" must be greater than 0.")

        hx_manager = FireEyeHXManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl)

        for entity in siemplify.target_entities:
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error(u"Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break

            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info(u"Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue

                siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
                matching_hosts = []

                if entity.entity_type == EntityTypes.HOSTNAME:
                    siemplify.LOGGER.info(u"Fetching host for hostname {}".format(entity.identifier))
                    matching_hosts = hx_manager.get_hosts(host_name=entity.identifier)

                elif entity.entity_type == EntityTypes.ADDRESS:
                    siemplify.LOGGER.info(u"Fetching host for address {}".format(entity.identifier))
                    matching_hosts = hx_manager.get_hosts_by_ip(ip_address=entity.identifier)

                if not matching_hosts:
                    siemplify.LOGGER.info(u"Matching host was not found for entity.".format(entity.identifier))
                    failed_entities.append(entity)
                    continue

                # Take endpoint with the most recent last_poll_timestamp
                host = sorted(matching_hosts, key=lambda matching_host: matching_host.last_poll_timestamp)[-1]
                siemplify.LOGGER.info(u"Matching host was found for {}".format(entity.identifier))

                alert_groups = hx_manager.get_alert_groups(
                    host_id=host._id,
                    acknowledgement=acknowledgement,
                    limit=limit)

                if alert_groups:
                    json_results[entity.identifier] = [group.to_json() for group in alert_groups]
                    siemplify.LOGGER.info(u"Found {} alert groups for {}".format(len(alert_groups), entity.identifier))
                    siemplify.result.add_data_table(u"Alert Groups - {}".format(entity.identifier),
                                                    construct_csv([group.as_csv() for group in alert_groups]))
                    successful_entities.append(entity)
                else:
                    siemplify.LOGGER.info(u"No alert groups were found for {}".format(entity.identifier))
                    failed_entities.append(entity)

                siemplify.LOGGER.info(u"Finished processing entity {0}".format(entity.identifier))

            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            output_message += u"Successfully retrieved alert groups for the following entities in {}:\n  {}".format(
                INTEGRATION_NAME, u"\n   ".join([entity.identifier for entity in successful_entities])
            )

            if failed_entities:
                output_message += u"\n\nAction wasn't able to retrieve alert groups for the following entities in {}:" \
                                  u"\n  {}".format(INTEGRATION_NAME, u"\n   ".join([entity.identifier for entity in
                                                                                    failed_entities]))
        else:
            result_value = False
            output_message = u"No alert groups were found for the provided entities in {}.".format(INTEGRATION_NAME)

    except Exception as e:
        siemplify.LOGGER.error(u"Failed to execute action! Error is {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = u"Error executing action \"{}\". Reason: {}".format(SCRIPT_NAME, e)

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
