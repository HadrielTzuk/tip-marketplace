from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler, convert_dict_to_json_result_dict
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from ScreenshotMachineManager import ScreenshotMachineManager, \
    ScreenshotMachineLimitManagerError, ScreenshotMachineInvalidAPIKeyManagerError
import base64
import requests
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED,EXECUTION_STATE_TIMEDOUT
from TIPCommon import extract_configuration_param, extract_action_param

SCRIPT_NAME = "ScreenshotMachine - TakeScreenshot"
INTEGRATION_NAME = "ScreenshotMachine"
DEFAULT_DELAY = 2000

SUPPORTED_ENTITIES = [EntityTypes.URL, EntityTypes.ADDRESS, EntityTypes.HOSTNAME]

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    siemplify.LOGGER.info("================= Main - Param Init =================")

    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key", input_type=unicode)
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Use SSL", default_value=False, input_type=bool)

    image_format = extract_action_param(siemplify, param_name="Image Format", input_type=unicode)

    delay = int(siemplify.parameters.get("Delay", DEFAULT_DELAY)) if siemplify.parameters.get("Delay") else DEFAULT_DELAY

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    json_results = {}

    try:
        screenshot_machine_manager = ScreenshotMachineManager(api_key, use_ssl=use_ssl)
        status = EXECUTION_STATE_COMPLETED
        output_message = ""
        result_value = False
        failed_entities = []
        successful_entities = []

        for entity in siemplify.target_entities:
            current_entity_identifier = entity.additional_properties.get('OriginalIdentifier', entity.identifier)
            siemplify.LOGGER.info(u"Started processing entity: {}".format(current_entity_identifier))
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error("Timed out. execution deadline ({}) has passed".format(convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break

            if entity.entity_type in SUPPORTED_ENTITIES:
                try:
                    screenshot_content = screenshot_machine_manager.get_screenshot(
                        current_entity_identifier,
                        image_format=image_format,
                        delay=delay)

                    # Attach screenshot
                    siemplify.result.add_entity_attachment(current_entity_identifier,
                                                           "Screenshot.{}".format(
                                                               image_format),
                                                           base64.b64encode(
                                                               screenshot_content))

                    json_results[current_entity_identifier] = base64.b64encode(screenshot_content)

                    successful_entities.append(current_entity_identifier)
                    siemplify.LOGGER.info(u"Finished processing entity {0}".format(current_entity_identifier))

                except (ScreenshotMachineInvalidAPIKeyManagerError, requests.exceptions.ConnectionError):
                    raise

                except ScreenshotMachineLimitManagerError:
                    status = EXECUTION_STATE_FAILED
                    result_value = False
                    output_message = "You have reached the maximum allowed number of API requests."
                    siemplify.end(output_message, result_value, status)

                except Exception as e:
                    failed_entities.append(current_entity_identifier)
                    siemplify.LOGGER.error(u"An error occurred on entity {0}".format(current_entity_identifier))
                    siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += u"\n Successfully returned screenshot for the following entities:\n   {}".format(u"\n   ".join(successful_entities))
            result_value = True

        if failed_entities:
            output_message += u"\n Action wasn't able to return screenshot for the following entities:\n   {}".format(
                u"\n   ".join(failed_entities))

        if not failed_entities and not successful_entities:
            output_message = "Action wasn't able to return screenshot for the provided entities."

    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = u"An error occurred while running action: {}".format(e)

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
