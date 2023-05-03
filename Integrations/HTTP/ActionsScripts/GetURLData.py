import urllib.parse

import requests
from TIPCommon import extract_action_param

from ScriptResult import EXECUTION_STATE_TIMEDOUT, EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime, convert_dict_to_json_result_dict

SCRIPT_NAME = "Get URL Data"
INTEGRATION_NAME = "HTTP"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)

    siemplify.LOGGER.info("================= Main - Param Init =================")

    username = extract_action_param(siemplify, param_name="Username", is_mandatory=False,
                                    input_type=str, print_value=True)

    password = extract_action_param(siemplify, param_name="Password", is_mandatory=False,
                                    input_type=str, print_value=False)

    ssl_verify = extract_action_param(siemplify, param_name="SSL Verification", is_mandatory=False,
                                      input_type=bool, default_value=False, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    result_value = "false"
    failed_entities = []
    successful_entities = []
    json_results = {}

    try:
        for entity in siemplify.target_entities:
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error("Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break

            if entity.entity_type == EntityTypes.URL:
                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))

                try:
                    if not urllib.parse.urlparse(entity.identifier).scheme:
                        siemplify.LOGGER.info("No schema in the URL. Prepending http://")
                        url = "http://" + entity.identifier

                    else:
                        url = entity.identifier

                    siemplify.LOGGER.info("Sending GET request to {}".format(url))

                    if username and password:
                        try:
                            response = requests.get(url, auth=(username, password), verify=ssl_verify)
                        except requests.exceptions.InvalidSchema:
                            siemplify.LOGGER.info("No schema in the URL. Prepending http://")
                            url = "http://" + entity.identifier
                            response = requests.get(url, auth=(username, password), verify=ssl_verify)

                    else:
                        try:
                            response = requests.get(url, verify=ssl_verify)
                        except requests.exceptions.InvalidSchema:
                            siemplify.LOGGER.info("No schema in the URL. Prepending http://")
                            url = "http://" + entity.identifier
                            response = requests.get(url, verify=ssl_verify)

                    siemplify.LOGGER.info("Response Code: {0}".format(response.status_code))
                    response.raise_for_status()

                    json_results[entity.identifier] = {
                        'data': response.text,
                        'redirects': [redirect.url for redirect in response.history]
                    }

                    successful_entities.append(entity.identifier)
                    siemplify.LOGGER.info("Finished processing entity {0}".format(entity.identifier))

                except Exception as e:
                    failed_entities.append(entity.identifier)
                    siemplify.LOGGER.error("An error occurred on entity {0}".format(entity.identifier))
                    siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += "Successfully processed entities:\n   {}".format("\n   ".join(successful_entities))
            result_value = "true"

        if failed_entities:
            output_message += "\n\n Failed processing entities:\n   {}".format("\n   ".join(failed_entities))

        if not failed_entities and not successful_entities:
            output_message = "No entities were processed."

    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = "An error occurred while running action: {}".format(e)

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
