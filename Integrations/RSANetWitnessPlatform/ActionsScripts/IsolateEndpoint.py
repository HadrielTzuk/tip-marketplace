from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from RSAManager import RSAManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import (
    INTEGRATION_NAME,
    ISOLATE_ENDPOINT_SCRIPT_NAME
)
from RSAExceptions import (
    IsolationFailException
)

SUPPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ISOLATE_ENDPOINT_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Configuration.
    ui_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Web API Root")
    ui_username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Web Username")
    ui_password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Web Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    # Parameters
    comment = extract_action_param(siemplify, param_name="Comment", input_type=str, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_messages = []
    successful_entities = []
    failed_entities = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

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
                try:
                    rsa_manager.isolate_endpoint(agent_id=entity_object.agent_id, service_id=service_object.id,
                                                 comment=comment)
                    successful_entities.append(entity)
                except IsolationFailException as e:
                    siemplify.LOGGER.error(str(e))
                    failed_entities.append(entity)
            else:
                failed_entities.append(entity)

            siemplify.LOGGER.info("Finished processing entity {}".format(entity.identifier))

        if successful_entities:
            output_messages.append('Successfully requested isolation for the following endpoints from RSA Netwitness: '
                                   '{}'.format("\n".join([entity.identifier for entity in successful_entities])))

        if failed_entities:
            result_value = False
            output_messages.append("Action was not able to request isolation for the following endpoints from "
                                   "RSA Netwitness: {}".format("\n".join([entity.identifier for entity in
                                                                          failed_entities])))

        output_message = '\n'.join(output_messages)

        if not suitable_entities:
            output_message = "No entities were isolated."
            result_value = False

    except Exception as e:
        output_message = "Error executing action \"Isolate Endpoint\". Reason: {}".format(e)
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