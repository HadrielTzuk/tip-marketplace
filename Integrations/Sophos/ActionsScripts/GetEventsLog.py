import datetime
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler, flat_dict_to_csv, dict_to_flat, \
    utc_now, construct_csv, convert_dict_to_json_result_dict, convert_datetime_to_unix_time
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SophosManager import SophosManager
from TIPCommon import extract_configuration_param, extract_action_param
from constants import GET_EVENTS_LOG_SCRIPT_NAME, INTEGRATION_NAME
from utils import get_entity_original_identifier, validated_limit

SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_EVENTS_LOG_SCRIPT_NAME
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True, input_type=unicode)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Client ID",
                                            is_mandatory=True, input_type=unicode)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Client Secret",
                                                is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    siem_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"SIEM API Root",
                                                input_type=unicode)

    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Key",
                                          input_type=unicode)

    base64_payload = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name=u"Base 64 Auth Payload", input_type=unicode)

    time_delta = extract_action_param(siemplify, param_name=u"Timeframe", is_mandatory=True, default_value=12,
                                      input_type=int)
    limit = extract_action_param(siemplify, param_name=u"Max Events To Return", default_value=50, input_type=int)

    if time_delta > 24:
        time_delta = 24
    start_time = (utc_now() - datetime.timedelta(hours=time_delta))
    start_time = int(convert_datetime_to_unix_time(start_time) / 1000)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")


    try:
        if not siem_api_root and not siem_api_root and not api_key:
            siemplify.LOGGER.exception("Failed to run action")

            raise Exception(u"'SIEM API Root', 'API Key' and 'Base 64 Auth Payload' should be provided.")
        validated_limit(limit)
        manager = SophosManager(api_root=api_root, client_id=client_id, client_secret=client_secret,
                                verify_ssl=verify_ssl, siem_api_root=siem_api_root, api_key=api_key,
                                api_token=base64_payload, test_connectivity=True)
        status = EXECUTION_STATE_COMPLETED
        successful_entities, failed_entities, no_events_entities, json_result = [], [], [], {}
        result_value = True
        output_message = u""
        suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITIES]

        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)
            entity_type = entity.entity_type
            siemplify.LOGGER.info(u"Started processing entity: {0}".format(entity_identifier))

            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error(u"Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break

            try:
                endpoint = manager.find_entities(entity_identifier=entity_identifier, entity_type=entity_type)

                if not endpoint:
                    siemplify.LOGGER.info(u"Endpoint was not found for entity {}. Skipping.".format(entity_identifier))
                    failed_entities.append(entity_identifier)
                    continue

                # Get endpoint's events
                events = manager.get_events_by_endpoint(endpoint_id=endpoint.scan_id, since=start_time, limit=limit)

                if not events:
                    no_events_entities.append(entity_identifier)
                    siemplify.LOGGER.info(u"No events were found for entity {}".format(entity_identifier))
                    continue

                flat_events = []
                json_result[entity_identifier] = {"events": [event.to_json() for event in events]}
                for event in events:
                    flat_events.append(dict_to_flat(event.to_csv()))

                csv_output = construct_csv(flat_events)
                siemplify.result.add_entity_table(entity_identifier, csv_output)

                successful_entities.append(entity_identifier)
                siemplify.LOGGER.info(u"Finished processing entity {0}".format(entity_identifier))

            except Exception as e:
                failed_entities.append(entity_identifier)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity_identifier))
                siemplify.LOGGER.exception(e)
        if json_result:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_result))

        if failed_entities:
            output_message += u"\nThe following entities were not found in {}:" \
                              u"\n   {}\n".format(INTEGRATION_NAME, u", ".join(failed_entities))
        if no_events_entities:
            output_message += u"\nNo events were found for the following endpoints in {}:" \
                              u"\n   {}\n".format(INTEGRATION_NAME, u", ".join(no_events_entities))
        if successful_entities:
            output_message += u"Successfully retrieved events related to the following endpoints in {}:" \
                             u"\n   {}\n".format(INTEGRATION_NAME, u", ".join(successful_entities))
        elif failed_entities and not no_events_entities:
            output_message = u"None of the provided entities were found in {}.".format(INTEGRATION_NAME)
            result_value = False
        elif not failed_entities and no_events_entities:
            output_message = u"No events were found for the provided endpoints in  {}.".format(INTEGRATION_NAME)


    except Exception as e:
        siemplify.LOGGER.error(u"General error occurred while running action {}".format(GET_EVENTS_LOG_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = u"Error executing action {}. Reason: {}".format(GET_EVENTS_LOG_SCRIPT_NAME, e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"is_success: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
