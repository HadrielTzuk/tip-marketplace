from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from RSAManager import RSAManager
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import (
    INTEGRATION_NAME,
    ENRICH_ENDPOINT_SCRIPT_NAME,
    ENRICHMENT_PREFIX
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_ENDPOINT_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Configuration.
    ui_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Web API Root")
    ui_username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Web Username")
    ui_password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Web Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    # Parameters
    risk_score_threshold = extract_action_param(siemplify, param_name="Risk Score Threshold", input_type=int)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""
    json_results = {}
    successful_entities = []
    failed_entities = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS
                         or entity.entity_type == EntityTypes.HOSTNAME]

    try:
        rsa_manager = RSAManager(ui_api_root=ui_api_root, ui_username=ui_username, ui_password=ui_password,
                                 verify_ssl=verify_ssl)

        service_object = rsa_manager.find_required_service_id()
        for entity in suitable_entities:
            siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))
            if entity.entity_type == EntityTypes.ADDRESS:
                entity_object = rsa_manager.search_for_ip(service_id=service_object.id, value=entity.identifier)
            else:
                entity_object = rsa_manager.search_for_host(service_id=service_object.id, value=entity.identifier)

            if entity_object:
                enrichment_data = entity_object.to_enrichment_data(prefix=ENRICHMENT_PREFIX)
                entity.additional_properties.update(enrichment_data)
                entity.is_enriched = True
                if risk_score_threshold and entity_object.risk_score > risk_score_threshold:
                    entity.is_suspicious = True

                # JSON result
                json_results[entity.identifier] = entity_object.to_json()
                siemplify.LOGGER.info(
                    'Successfully enriched the following endpoint from RSA NetWitness: {}'.format(entity.identifier))
                successful_entities.append(entity)
            else:
                failed_entities.append(entity)

            siemplify.LOGGER.info("Finished processing entity {}".format(entity.identifier))

        if successful_entities:
            siemplify.update_entities(successful_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            output_message += 'Successfully enriched the following endpoints from RSA NetWitness: {}'.format(
                "\n".join([entity.identifier for entity in successful_entities]))

        if failed_entities:
            output_message += "\n\n Action was not able to enrich the following endpoints from RSA NetWitness: {}"\
                .format("\n".join([entity.identifier for entity in failed_entities]))

        if not successful_entities:
            output_message = "No entities were enriched."
            result_value = False

    except Exception as e:
        output_message = "Error executing action \"Enrich Endpoint\". Reason: {}".format(e)
        result_value = False
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()