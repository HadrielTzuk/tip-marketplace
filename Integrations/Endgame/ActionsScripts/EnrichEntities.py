from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler, add_prefix_to_dict_keys,\
     convert_dict_to_json_result_dict, flat_dict_to_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from EndgameManager import EndgameManager, EndgameNotFoundError
from TIPCommon import extract_configuration_param

INTEGRATION_NAME = u"Endgame"
SCRIPT_NAME = u"Enrich Entities"
SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


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

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    missing_entities = []
    json_results = {}
    failed_entities = []
    output_message = u""
    result_value = "true"

    try:
        endgame_manager = EndgameManager(api_root, username, password, verify_ssl)

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
                matching_endpoints = []

                if entity.entity_type == EntityTypes.HOSTNAME:
                    try:
                        siemplify.LOGGER.info(u"Fetching endpoint for hostname {}".format(entity.identifier))
                        matching_endpoints = endgame_manager.get_endpoint_by_hostname(entity.identifier)
                    except EndgameNotFoundError as e:
                        # Endpoint was not found in Endgame - skip entity
                        missing_entities.append(entity)
                        siemplify.LOGGER.info(unicode(e))
                        siemplify.LOGGER.info(u"Skipping entity {}".format(entity.identifier))
                        continue

                if entity.entity_type == EntityTypes.ADDRESS:
                    try:
                        siemplify.LOGGER.info(u"Fetching endpoint for address {}".format(entity.identifier))
                        matching_endpoints = endgame_manager.get_endpoint_by_ip(entity.identifier)
                    except EndgameNotFoundError as e:
                        # Endpoint was not found in Endgame - skip entity
                        missing_entities.append(entity)
                        siemplify.LOGGER.info(unicode(e))
                        siemplify.LOGGER.info(u"Skipping entity {}".format(entity.identifier))
                        continue

                if len(matching_endpoints) > 1:
                    siemplify.LOGGER.info(
                        u"Multiple endpoints matching entity {} were found. First will be used.".format(
                            entity.identifier)
                    )

                # Take the first matching endpoint
                endpoint = matching_endpoints[0]

                entity.additional_properties.update(
                    add_prefix_to_dict_keys(endpoint.as_enrichment_data(), INTEGRATION_NAME)
                )

                json_results[entity.identifier] = endpoint.raw_data
                siemplify.result.add_entity_table(u"Entity {0} details found".format(entity.identifier),
                                                  flat_dict_to_csv(endpoint.as_csv()))
                entity.is_enriched = True

                successful_entities.append(entity)
                siemplify.LOGGER.info(u"Finished processing entity {0}".format(entity.identifier))

            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += u"Successfully enriched entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in successful_entities])
            )
            siemplify.update_entities(successful_entities)
        else:
            output_message += u"No entities were enriched."

        if missing_entities:
            output_message += u"\n\nAction was not able to find Endgame info to enrich provided entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in missing_entities])
            )

        if failed_entities:
            output_message += u"\n\nFailed enriching the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in failed_entities])
            )

    except Exception as e:
        siemplify.LOGGER.error(u"Action didn't complete due to error: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = u"Action didn't complete due to error: {}".format(e)

    finally:
        try:
            endgame_manager.logout()
        except Exception as e:
            siemplify.LOGGER.error(u"Logging out failed. Error: {}".format(e))
            siemplify.LOGGER.exception(e)

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
