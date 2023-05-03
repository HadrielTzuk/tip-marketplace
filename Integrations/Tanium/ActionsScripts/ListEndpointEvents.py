from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict, convert_unixtime_to_datetime
from TaniumManager import TaniumManager
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from exceptions import InvalidTimeException
from constants import INTEGRATION_NAME, LIST_ENDPOINT_EVENTS_SCRIPT_NAME, EVENT_TYPE_MAPPING, \
    DEFAULT_ACTION_LIMIT, DEFAULT_SORT_FIELD, ASC_SORT_ORDER, CONNECTED_STATUS
from utils import get_timestamps, get_entity_original_identifier
from time import sleep


SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_ENDPOINT_EVENTS_SCRIPT_NAME
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True, print_value=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True, remove_whitespaces=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             input_type=bool, print_value=True)

    # action parameters
    event_type = extract_action_param(siemplify, param_name="Event Type", is_mandatory=False, print_value=True)
    timeframe = extract_action_param(siemplify, param_name="Time Frame", is_mandatory=False, print_value=True)
    start_time_string = extract_action_param(siemplify, param_name="Start Time", is_mandatory=False, print_value=True)
    end_time_string = extract_action_param(siemplify, param_name="End Time", is_mandatory=False, print_value=True)
    sort_field = extract_action_param(siemplify, param_name="Sort Field", is_mandatory=False, print_value=True,
                                      default_value=DEFAULT_SORT_FIELD)
    sort_order = extract_action_param(siemplify, param_name="Sort Order", is_mandatory=False, print_value=True,
                                      default_value=ASC_SORT_ORDER)
    limit = extract_action_param(siemplify, param_name="Max Events To Return", is_mandatory=False, print_value=True,
                                 default_value=DEFAULT_ACTION_LIMIT, input_type=int)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    if limit < 1:
        siemplify.LOGGER.info(f"\"Max Events To Return\" must be non-negative. Using default of {DEFAULT_ACTION_LIMIT}.")
        limit = DEFAULT_ACTION_LIMIT

    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    missing_entities = []
    failed_entities = []
    json_results = {}
    output_message = ""
    result_value = True

    try:
        alert_start_time = convert_unixtime_to_datetime(
            int(siemplify._current_alert.additional_properties.get("StartTime")))
        alert_end_time = convert_unixtime_to_datetime(
            int(siemplify._current_alert.additional_properties.get("EndTime")))

        start_time, end_time = get_timestamps(range_string=timeframe,
                                              start_time_string=start_time_string,
                                              end_time_string=end_time_string,
                                              alert_start_time=alert_start_time,
                                              alert_end_time=alert_end_time)

        manager = TaniumManager(api_root=api_root, api_token=api_token, verify_ssl=verify_ssl,
                                force_check_connectivity=True, logger=siemplify.LOGGER)
        open_connections = manager.get_open_connections()

        for entity in siemplify.target_entities:
            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info("Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue

                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))
                entity_identifier = get_entity_original_identifier(entity)
                entity_connections = [connection for connection in open_connections if entity_identifier in
                                      [connection.ip, connection.hostname]]
                if entity_connections:
                    enabled_connection = next((connection for connection in entity_connections if connection.status ==
                                               CONNECTED_STATUS), None)
                    siemplify.LOGGER.info("Found connection for {}".format(entity.identifier))
                    if not enabled_connection:
                        siemplify.LOGGER.info("Disabled. Creating connection... ")
                        manager.create_conection(hostname=entity_connections[0].hostname,
                                                 ip=entity_connections[0].ip,
                                                 client_id=entity_connections[0].client_id,
                                                 platform=entity_connections[0].platform)
                        for i in range(3):
                            siemplify.LOGGER.info("Checking connection status... ")
                            sleep(5)
                            open_connections = manager.get_open_connections()
                            entity_connections = [connection for connection in open_connections if entity_identifier in
                                                  [connection.ip, connection.hostname]]
                            enabled_connection = next(
                                (connection for connection in entity_connections if connection.status ==
                                 CONNECTED_STATUS), None)
                            if enabled_connection:
                                break
                        if not enabled_connection:
                            siemplify.LOGGER.info(f"Connection was not enabled. Skipping entity {entity_identifier}.")
                            failed_entities.append(entity)
                            continue
                        connection_id = enabled_connection.id
                    else:
                        connection_id = enabled_connection.id
                    siemplify.LOGGER.info("Fetching events for {}".format(entity.identifier))
                    events = manager.get_connection_events(connection_id=connection_id,
                                                           start_time=start_time,
                                                           end_time=end_time,
                                                           sort_field=sort_field,
                                                           sort_order=sort_order,
                                                           event_type=EVENT_TYPE_MAPPING.get(event_type),
                                                           limit=limit)
                    json_results[entity.identifier] = events
                    if events:
                        successful_entities.append(entity)
                    else:
                        missing_entities.append(entity)
                else:
                    siemplify.LOGGER.info("No connection found for {}".format(entity.identifier))
                    failed_entities.append(entity)

                siemplify.LOGGER.info("Finished processing entity {}".format(entity.identifier))

            except Exception as e:
                failed_entities.append(entity)
                json_results[entity.identifier] = []
                siemplify.LOGGER.error("An error occurred on entity {}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += "Successfully returned events for the following endpoints in Tanium:\n{}\n\n".format(
                "\n".join([entity.identifier for entity in successful_entities])
            )

        if missing_entities:
            output_message += "No events were found for the following endpoints in Tanium:\n{}\n\n".format(
                "\n".join([entity.identifier for entity in missing_entities])
            )

        if failed_entities:
            output_message += "Action wasn't able to retrieve information about events from the following endpoints " \
                              "in Tanium due to agent connectivity issues:\n{}\nPlease make sure that those " \
                              "hostnames are connected to the Tanium Threat Response " \
                              "module.".format("\n".join([entity.identifier for entity in failed_entities]))

        if not successful_entities:
            result_value = False
            if not failed_entities and missing_entities:
                output_message = "No information about IOCs were found."
            elif not missing_entities and failed_entities:
                raise Exception("action wasn't able to retrieve information about events from the provided endpoints "
                                "in Tanium due to agent connectivity issues. Please make sure that those hostnames "
                                "are connected to the Tanium Threat Response module.")
            elif not missing_entities and not failed_entities:
                output_message = "No suitable entities were found in the scope."

        if successful_entities or failed_entities or missing_entities:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    except InvalidTimeException:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{LIST_ENDPOINT_EVENTS_SCRIPT_NAME}\". Reason: \"Start Time\" " \
                         f"should be provided, when \"Custom\" is selected in \"Time Frame\" parameter."

    except Exception as e:
        siemplify.LOGGER.error(f"Error executing action \"{LIST_ENDPOINT_EVENTS_SCRIPT_NAME}\". Reason: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Error executing action \"{LIST_ENDPOINT_EVENTS_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
