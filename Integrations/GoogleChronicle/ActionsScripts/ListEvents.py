from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime, convert_dict_to_json_result_dict, \
    get_domain_from_entity
from GoogleChronicleManager import GoogleChronicleManager
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from TIPCommon import extract_configuration_param, extract_action_param
from exceptions import InvalidTimeException
import consts
import utils
import json
from collections import Counter


SCRIPT_NAME = "List Events"
SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME, EntityTypes.MACADDRESS]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{consts.INTEGRATION_NAME} - {SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    creds = extract_configuration_param(siemplify, provider_name=consts.INTEGRATION_NAME,
                                        param_name="User's Service Account",
                                        is_mandatory=True)
    api_root = extract_configuration_param(siemplify, provider_name=consts.INTEGRATION_NAME,
                                           param_name="API Root", is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=consts.INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    try:
        creds = json.loads(creds)
    except Exception as e:
        siemplify.LOGGER.error("Unable to parse credentials as JSON.")
        siemplify.LOGGER.exception(e)
        siemplify.end("Unable to parse credentials as JSON. Please validate creds.", "false", EXECUTION_STATE_FAILED)

    event_types = extract_action_param(siemplify, param_name="Event Types", is_mandatory=False, print_value=True)
    timeframe = extract_action_param(siemplify, param_name="Time Frame", is_mandatory=False, print_value=True)
    start_time_string = extract_action_param(siemplify, param_name="Start Time", is_mandatory=False, print_value=True)
    end_time_string = extract_action_param(siemplify, param_name="End Time", is_mandatory=False, print_value=True)
    reference_time = extract_action_param(siemplify, param_name="Reference Time", is_mandatory=False, print_value=True)
    output_type = extract_action_param(siemplify, param_name="Output", is_mandatory=False, print_value=True)
    limit = extract_action_param(siemplify, param_name="Max Events To Return", is_mandatory=False, print_value=True,
                                 default_value=consts.DEFAULT_LIMIT, input_type=int)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    if limit < 0:
        siemplify.LOGGER.info(f"\"Max Events To Return\" must be non-negative. Using default of {consts.DEFAULT_LIMIT}.")
        limit = consts.DEFAULT_LIMIT

    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    missing_entities = []
    failed_entities = []
    json_results = {}
    output_message = ""
    result_value = "false"

    try:
        event_types = utils.convert_comma_separated_to_list(event_types)
        if [event_type for event_type in event_types if event_type.upper() not in consts.EVENT_TYPES]:
            raise Exception(f"invalid event type is provided. Please check the spelling. Supported event types: "
                            f"{utils.convert_list_to_comma_string(consts.EVENT_TYPES)}")

        start_time, end_time = utils.get_timestamps(timeframe, start_time_string, end_time_string)

        manager = GoogleChronicleManager(api_root=api_root, verify_ssl=verify_ssl, **creds)

        for entity in siemplify.target_entities:
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error("Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break

            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info("Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue

                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))
                siemplify.LOGGER.info("Fetching events for {}".format(entity.identifier))

                events = []
                uri = []

                if entity.entity_type == EntityTypes.ADDRESS:
                    uri, events = manager.list_events(start_time=start_time, end_time=end_time,
                                                      reference_time=reference_time, ip=entity.identifier, limit=limit,
                                                      event_types=event_types)

                elif entity.entity_type == EntityTypes.HOSTNAME:
                    uri, events = manager.list_events(start_time=start_time, end_time=end_time,
                                                      reference_time=reference_time, hostname=entity.identifier,
                                                      limit=limit, event_types=event_types)

                elif entity.entity_type == EntityTypes.MACADDRESS:
                    uri, events = manager.list_events(start_time=start_time, end_time=end_time,
                                                      reference_time=reference_time, mac=entity.identifier, limit=limit,
                                                      event_types=event_types)

                siemplify.LOGGER.info("Found {} events for {}".format(len(events), entity.identifier))

                statistics_dict = {}
                counted_events = Counter(item.event_type for item in events)
                for t, count in counted_events.items():
                    statistics_dict[t] = count

                if output_type == consts.ONLY_EVENTS:
                    json_results[entity.identifier] = {"events": [event.raw_data for event in events], "uri": uri}
                elif output_type == consts.ONLY_STATISTICS:
                    json_results[entity.identifier] = {"statistics": statistics_dict, "uri": uri}
                elif output_type == consts.EVENTS_AND_STATISTICS:
                    json_results[entity.identifier] = {"statistics": statistics_dict,
                                                       "events": [event.raw_data for event in events],
                                                       "uri": uri}

                if events:
                    successful_entities.append(entity)

                else:
                    missing_entities.append(entity)

                siemplify.LOGGER.info("Finished processing entity {0}".format(entity.identifier))

            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error("An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += "Successfully listed related events for the following entities from Google Chronicle:\n   {}\n\n".format(
                "\n   ".join([entity.identifier for entity in successful_entities])
            )
            siemplify.update_entities(successful_entities)
            result_value = "true"

        if missing_entities:
            output_message += "No related events were found for the following entities from Google Chronicle:\n   {}\n\n".format(
                "\n   ".join([entity.identifier for entity in missing_entities])
            )
            result_value = "true"

        if not successful_entities and not missing_entities:
            output_message += "No events were found for the provided entities.\n\n"

        if failed_entities:
            output_message += "Action was not able to list related events for the following entities from Google Chronicle:\n   {}".format(
                "\n   ".join([entity.identifier for entity in failed_entities])
            )

    except InvalidTimeException:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{SCRIPT_NAME}\". Reason: \"Start Time\" " \
                         f"should be provided, when \"Custom\" is selected in \"Time Frame\" parameter."

    except Exception as e:
        siemplify.LOGGER.error(f"Error executing action \"{SCRIPT_NAME}\". Reason: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = f"Error executing action \"{SCRIPT_NAME}\". Reason: {e}"

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
