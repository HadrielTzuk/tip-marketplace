import json

import requests
from TIPCommon import extract_action_param

from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME, POST_DATA_SCRIPT_NAME, NONE_CONTENT_TYPE, APPLICATION_JSON_CONTENT_TYPE


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, POST_DATA_SCRIPT_NAME)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    url = extract_action_param(siemplify, param_name="URL", is_mandatory=True, print_value=True)
    username = extract_action_param(siemplify, param_name="Username", is_mandatory=False,
                                    input_type=str, print_value=True)

    password = extract_action_param(siemplify, param_name="Password", is_mandatory=False,
                                    input_type=str, print_value=False)

    ssl_verify = extract_action_param(siemplify, param_name="SSL Verification", is_mandatory=False,
                                      input_type=bool, default_value=False, print_value=True)

    headers_str = extract_action_param(siemplify, param_name="Headers JSON", is_mandatory=False, print_value=True)
    data = extract_action_param(siemplify, param_name="Data", is_mandatory=True, print_value=True)
    content_type = extract_action_param(siemplify, param_name="Content Type", default_value=NONE_CONTENT_TYPE, is_mandatory=True,
                                        print_value=True)
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    headers = {}
    json_results = {
        'data': "",
        'redirects': []
    }

    try:
        if headers_str:
            headers = json.loads(headers_str)
            siemplify.LOGGER.info(f"Loaded json headers")
    except Exception as error:
        siemplify.LOGGER.error(f"Failed to load headers to json. Error is: {error}")

    try:

        request_attributes = {
            'url': url,
            'verify': ssl_verify
        }

        # Use basic auth
        if username and password:
            request_attributes.update({'auth': (username, password)})

        # Use Content Type
        if content_type != NONE_CONTENT_TYPE:
            headers.update({"content-type": content_type})

        # Use headers
        if headers:
            request_attributes.update({'headers': headers})

        if content_type == APPLICATION_JSON_CONTENT_TYPE:
            try:
                request_attributes['json'] = json.loads(data)
                siemplify.LOGGER.info(f"Loaded json data")
            except Exception as error:
                siemplify.LOGGER.error(f"Failed to load json data. Error is: {error}")
                request_attributes['data'] = data.encode("utf-8")
        else:
            request_attributes['data'] = data.encode("utf-8")

        response = requests.post(**request_attributes)

        # Check for bad status code
        try:
            response.raise_for_status()
        except Exception as e:
            raise Exception("{0}, {1}".format(e, response.text))

        try:
            json_results['data'] = response.json()
        except:
            json_results['data'] = response.text

        json_results['redirects'] = [redirect.url for redirect in response.history]
        siemplify.result.add_result_json(json_results)
        result_value = response.text
        output_message = "Response data: " + response.text

    except Exception as error:
        output_message = f"Error execution action \"{POST_DATA_SCRIPT_NAME}\". Error is: {error}"
        siemplify.LOGGER.info(output_message)
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
