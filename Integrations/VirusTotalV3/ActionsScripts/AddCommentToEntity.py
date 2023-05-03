from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param, extract_action_param
from UtilsManager import get_entity_original_identifier
from VirusTotalManager import VirusTotalManager
from constants import (
    INTEGRATION_NAME,
    ADD_COMMENT_TO_ENTITY_SCRIPT_NAME,
    PROVIDER_NAME
)

SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.FILEHASH, EntityTypes.URL, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_COMMENT_TO_ENTITY_SCRIPT_NAME

    # integration configuration
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool)
    # action parameters
    comment = extract_action_param(siemplify, param_name="Comment", print_value=False)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    result = True
    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    failed_entities = []
    json_result = {}

    try:
        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)

        siemplify.LOGGER.info("Testing connectivity to Virus Total.")
        manager.test_connectivity()

        for entity in siemplify.target_entities:
            identifier = get_entity_original_identifier(entity)
            if entity.entity_type in SUPPORTED_ENTITIES:
                try:
                    siemplify.LOGGER.info("Started processing entity: {}".format(identifier))
                    manager.add_comment_to_entity(entity, comment)
                    status = EXECUTION_STATE_COMPLETED
                    successful_entities.append(identifier)
                    json_result.update({
                        identifier: {
                            "Status": "Done"
                        }
                    })
                except Exception as e:
                    failed_entities.append(identifier)
                    json_result.update({
                        identifier: {
                            "Status": "Not done"
                        }
                    })
                    siemplify.LOGGER.error(u"An error occurred on entity {0}".format(identifier))
                    siemplify.LOGGER.exception(e)
        if successful_entities:
            output_message += "Successfully added comments to the following " \
                              "entities in {}: \n {} \n".format(PROVIDER_NAME, ', '.join(successful_entities))
            if failed_entities:
                output_message += "Action wasn't able to add comments to the following " \
                                  "entities in {}: \n {} \n".format(PROVIDER_NAME, ', '.join(failed_entities))
        else:
            result = False
            output_message = f"No comments were added to the provided entities in {PROVIDER_NAME}."

    except Exception as e:
        result = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(f"General error performing action {ADD_COMMENT_TO_ENTITY_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        output_message = f"Error executing action \"{ADD_COMMENT_TO_ENTITY_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_result))
    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
