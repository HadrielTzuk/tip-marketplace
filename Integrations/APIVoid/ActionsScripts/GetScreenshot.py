from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from APIVoidManager import APIVoidManager, APIVoidNotFound, APIVoidInvalidAPIKeyError
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from SiemplifyUtils import convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param, extract_action_param
import re
import urlparse

INTEGRATION_NAME = u"APIVoid"
SCRIPT_NAME = u"Get Screenshot"
SUPPORTED_ENTITIES = [EntityTypes.URL]


def strip_scheme(url):
    parsed = urlparse.urlparse(url)
    scheme = u"{}://".format(parsed.scheme)
    return parsed.geturl().replace(scheme, u'', 1)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Root",
                                           is_mandatory=True, input_type=unicode)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Key",
                                          is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    threshold = extract_action_param(siemplify, param_name=u"Threshold", is_mandatory=False,
                                     input_type=int, default_value=0,
                                     print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    result_value = u"true"
    output_message = u""
    successful_entities = []
    missing_entities = []
    too_big_entities = []
    failed_entities = []
    json_results = {}
    status = EXECUTION_STATE_COMPLETED

    try:
        apivoid_manager = APIVoidManager(api_root, api_key, verify_ssl=verify_ssl)

        for entity in siemplify.target_entities:
            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info(u"Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue

                siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))

                if not re.match(ur'^[a-zA-Z]+://', entity.identifier):
                    siemplify.LOGGER.info(u"Seems like schema is missing from the URL. Prepending http://")
                    url = u"http://" + entity.identifier

                else:
                    url = entity.identifier

                siemplify.LOGGER.info(u"Capturing screenshot for entity {}".format(entity.identifier))
                screenshot_obj = apivoid_manager.get_url_screenshot(url)

                if screenshot_obj.file_size_bytes > 3 * 1000000:
                    siemplify.LOGGER.error(u"Screenshot size is larger than 3MB. Unable to add screenshot as attachment.")
                    too_big_entities.append(entity)
                    continue

                siemplify.result.add_attachment(
                    u"Screenshot - {}".format(entity.identifier),
                    u"{}_capture.{}".format(strip_scheme(url), screenshot_obj.file_format),
                    screenshot_obj.base64_file
                )
                json_results[entity.identifier] = {u'file_md5_hash': screenshot_obj.file_md5_hash}
                successful_entities.append(entity)

            except APIVoidNotFound as e:
                siemplify.LOGGER.error(e)
                missing_entities.append(entity)

            except APIVoidInvalidAPIKeyError as e:
                siemplify.LOGGER.error(e)
                raise APIVoidInvalidAPIKeyError(u"API key is invalid.")

            except Exception as e:
                failed_entities.append(entity)
                # An error occurred - skip entity and continue
                siemplify.LOGGER.error(u"An error occurred on entity: {}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message = u"APIVoid: Added screenshots for the following entities:\n   {}\n\n".format(
                u"\n   ".join([entity.identifier for entity in successful_entities])
            )

            siemplify.update_entities(successful_entities)

        if too_big_entities:
            output_message += u"Failed to add screenshots as attachments on the following entities:\n   {}\n\n".format(
                u"\n   ".join([entity.identifier for entity in too_big_entities])
            )

        if missing_entities:
            output_message += u"No screenshots were found for the following entities:\n   {}\n\n".format(
                u"\n   ".join([entity.identifier for entity in missing_entities])
            )

        if failed_entities:
            output_message += u"An error occurred on the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in failed_entities])
            )

        if not (successful_entities or failed_entities or missing_entities or too_big_entities):
            output_message = u"No URL entities found for capturing screenshots."
            result_value = u"false"

    except Exception as e:
        siemplify.LOGGER.error(u"Action didn't complete due to error: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Action didn't complete due to error: {}".format(e)

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
