from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SophosManager import SophosManager, EndpointTypes
from TIPCommon import extract_configuration_param, construct_csv
from constants import INTEGRATION_NAME, GET_SERVICE_STATUS_SCRIPT_NAME
from utils import get_entity_original_identifier

SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_SERVICE_STATUS_SCRIPT_NAME
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

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    try:
        manager = SophosManager(api_root=api_root, client_id=client_id, client_secret=client_secret,
                                verify_ssl=verify_ssl, test_connectivity=True)

        status = EXECUTION_STATE_COMPLETED
        successful_entities, failed_entities, csv_output, json_results = [], [], [], {}
        output_message = u""
        result_value = True
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
                    failed_entities.append(entity_identifier)
                    continue
                json_results[entity_identifier] = endpoint.to_json()
                csv_output = [service_detail.to_csv() for service_detail in endpoint.service_details]
                siemplify.result.add_entity_table(entity.identifier, construct_csv(csv_output))
                successful_entities.append(entity_identifier)

            except Exception as e:
                failed_entities.append(entity_identifier)
                siemplify.LOGGER.error(u"An error occurred on entity {}".format(entity_identifier))
                siemplify.LOGGER.exception(e)

            siemplify.LOGGER.info(u"Finished processing entity {}".format(entity_identifier))

        if json_results:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
        if successful_entities:
            output_message += u"Successfully retrieved service information from the following entities in {}: " \
                              u"{}".format(INTEGRATION_NAME, u", ".join(successful_entities))

            if failed_entities:
                output_message += u"\nThe following entities were not found in {}: {}"\
                    .format(INTEGRATION_NAME, ", ".join(failed_entities))

        else:
            output_message += u"None of the provided entities were found in {}.".format(INTEGRATION_NAME)
            result_value = False

    except Exception as e:
        output_message = u"Error executing action {}. Reason: {}".format(GET_SERVICE_STATUS_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
