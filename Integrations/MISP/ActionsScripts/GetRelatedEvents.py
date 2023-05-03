from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SiemplifyUtils import convert_dict_to_json_result_dict, unix_now, convert_unixtime_to_datetime
from MISPManager import MISPManager, URL, HOSTNAME, DOMAIN, SRC_IP, DST_IP
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import GET_RELATED_EVENTS_SCRIPT_NAME, INTEGRATION_NAME, RELATED_EVENTS_TABLE_NAME
from utils import get_entity_original_identifier, get_hash_type

SUPPORTED_ENTITY_TYPES = [EntityTypes.URL, EntityTypes.HOSTNAME, EntityTypes.FILEHASH, EntityTypes.ADDRESS]
ENTITY_TYPE_MAPPER = {
    EntityTypes.URL: [URL],
    EntityTypes.HOSTNAME: [HOSTNAME, DOMAIN],
    EntityTypes.FILEHASH: [],
    EntityTypes.ADDRESS: [SRC_IP, DST_IP]
}


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_RELATED_EVENTS_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root")
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key")
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Use SSL",
                                          default_value=False, input_type=bool)
    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="CA Certificate File - parsed into Base64 String")

    events_limit = extract_action_param(siemplify, param_name="Events Limit", print_value=True, input_type=int)
    mark_as_suspicious = extract_action_param(siemplify, param_name="Mark As Suspicious", print_value=True,
                                              input_type=bool, default_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    result_json = {}
    successful_entities, enriched_entities, failed_entities = [], [], []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        misp_manager = MISPManager(api_root, api_token, use_ssl, ca_certificate)
        handled_event_ids = []
        for entity in suitable_entities:

            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error("Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break

            entity_identifier = get_entity_original_identifier(entity)

            try:
                siemplify.LOGGER.info("Started processing entity: {}".format(entity_identifier))
                entity_types = ENTITY_TYPE_MAPPER[entity.entity_type] if entity.entity_type != EntityTypes.FILEHASH \
                    else [get_hash_type(entity_identifier)]
                related_events = []

                for entity_type in entity_types:
                    for related_event in misp_manager.get_reputation(type=entity_type,
                                                                     limit=events_limit,
                                                                     entity=entity_identifier):
                        if related_event.id in handled_event_ids:
                            continue
                        handled_event_ids.append(related_event.id)
                        related_events.append(related_event)

                siemplify.LOGGER.info("Found {} events.".format(len(related_events)))

                if related_events:
                    # If records are available - then entity suspicious
                    siemplify.LOGGER.info("Adding events table.")
                    csv_output = [event.to_csv_as_related_event() for event in related_events]
                    siemplify.result.add_entity_table(RELATED_EVENTS_TABLE_NAME
                                                      .format(entity_identifier),
                                                      construct_csv(csv_output))
                    result_json[entity_identifier] = csv_output
                    successful_entities.append(entity_identifier)
                    if mark_as_suspicious:
                        entity.is_suspicious = True
                        enriched_entities.append(entity)
                else:
                    failed_entities.append(entity_identifier)

                siemplify.LOGGER.info("Finished processing entity {}".format(entity_identifier))

            except Exception as e:
                failed_entities.append(entity_identifier)
                siemplify.LOGGER.error("An error occurred on entity: {}.\n{}."
                                       .format(entity_identifier, e))
                siemplify.LOGGER.exception(e)

        if result_json:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(result_json))

        if successful_entities:
            output_message += "Successfully retrieved information about the related events for the following " \
                              "entities: \n {} \n".format(', '.join(successful_entities))
            if failed_entities:
                output_message += "Action wasn’t able to retrieve information about the related events for the " \
                                  "following entities: \n {} \n".format(', '.join(failed_entities))
        else:
            output_message = "No related events were found for the provided entities."
            result_value = False

        if enriched_entities:
            siemplify.update_entities(enriched_entities)

    except Exception as e:
        output_message = "Error executing action {}. Reason: {}".format(GET_RELATED_EVENTS_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("\n  status: {}\n  result_value: {}\n  output_message: {}"
                          .format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
