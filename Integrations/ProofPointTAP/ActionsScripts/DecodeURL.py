from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from TIPCommon import extract_configuration_param, extract_action_param, string_to_multi_value
from ProofPointTapManager import ProofPointTapManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from utils import get_entity_original_identifier
from constants import INTEGRATION_NAME, DECODE_URL_SCRIPT_NAME, INTEGRATION_DISPLAY_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.action_definition_name = DECODE_URL_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)
    encoded_urls = string_to_multi_value(extract_action_param(siemplify, param_name="Encoded URLs", print_value=True))
    create_url_entities = extract_action_param(siemplify, param_name="Create URL Entities", print_value=True,
                                               input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    json_result, successful_entities, failed_entities = [], [], []

    try:
        manager = ProofPointTapManager(server_address=api_root, username=username, password=password,
                                       verify_ssl=verify_ssl, force_check_connectivity=True)

        target_entities = [get_entity_original_identifier(entity) for entity in siemplify.target_entities if
                           entity.entity_type == EntityTypes.URL]

        decoded_urls = manager.decode_urls(urls=target_entities + encoded_urls)

        for decoded_url in decoded_urls:
            if decoded_url.success:
                json_result.append(decoded_url.to_json())

                if create_url_entities and decoded_url.encoded_url in encoded_urls:
                    siemplify.add_entity_to_case(entity_identifier=decoded_url.decoded_url,
                                                 entity_type=EntityTypes.URL,
                                                 is_internal=False, is_suspicous=False, is_enriched=False,
                                                 is_vulnerable=True, properties={'is_new_entity': True})
                successful_entities.append(decoded_url.encoded_url)

            else:
                siemplify.LOGGER.info(f'Error can not decode: {decoded_url.encoded_url}')
                failed_entities.append(decoded_url.encoded_url)

        if successful_entities:
            siemplify.result.add_result_json(json_result)
            output_message += f"Successfully decoded the following URLs in {INTEGRATION_DISPLAY_NAME}: " \
                              f"{', '.join(successful_entities)} \n"

            if failed_entities:
                output_message += f"Action wasn't able to decode the following URLs in {INTEGRATION_DISPLAY_NAME}:" \
                                  f" {', '.join(failed_entities)} \n"

        else:
            output_message = f'None of the provided URLs were decoded in {INTEGRATION_DISPLAY_NAME}.'
            result_value = False

    except Exception as e:
        output_message = f"Error executing action {DECODE_URL_SCRIPT_NAME}. Reason: {e}"
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
