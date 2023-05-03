from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from ActiveDirectoryManager import ActiveDirectoryManager
import sys
import base64
import json

# =====================================
#             CONSTANTS               #
# =====================================
INTEGRATION_NAME = "ActiveDirectory"
SCRIPT_NAME = "ActiveDirectory - SearchActiveDirectory"
SEARCH_PAGE_SIZE = 1000

@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    mode = 'Main' if is_first_run else 'QueryState'

    siemplify.LOGGER.info('----------------- {} - Param Init -----------------'.format(mode))

    # INIT INTEGRATION CONFIGURATIONS:
    server = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, is_mandatory=True, param_name="Server", input_type=str
    )
    username = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, is_mandatory=True, param_name="Username", input_type=str
    )
    password = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, is_mandatory=True, param_name="Password", input_type=str
    )
    domain = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, is_mandatory=True, param_name="Domain", input_type=str
    )
    use_ssl = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, is_mandatory=True, param_name="Use SSL", input_type=bool
    )
    custom_query_fields = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="Custom Query Fields", input_type=str
    )
    ca_certificate = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="CA Certificate File - parsed into Base64 String"
    )
    # INIT ACTION CONFIGURATIONS:
    query_string = extract_action_param(
        siemplify, param_name="Query String", is_mandatory=True, input_type=str, print_value=True
    )
    limit = extract_action_param(
        siemplify, param_name="Limit", input_type=int, print_value=True, default_value=0
    )
    limit = max(0, limit)

    siemplify.LOGGER.info('----------------- {} - Started -----------------'.format(mode))

    try:
        manager = ActiveDirectoryManager(server, domain, username, password, use_ssl, custom_query_fields,
                                         ca_certificate, siemplify.LOGGER)
        cookie = None
        fetched_entities = []

        if not is_first_run:
            fetched_entities, cookie = json.loads(siemplify.parameters['additional_data'])
            cookie = base64.b64decode(cookie)

        entities, cookie = manager.search_with_paging(query_string, SEARCH_PAGE_SIZE, cookie, limit)
        fetched_entities.extend(entities)

        if cookie and (len(fetched_entities) < limit):
            cookie = base64.b64encode(cookie).decode()
            output_message = 'Fetched {} entities'.format(len(fetched_entities))
            status = EXECUTION_STATE_INPROGRESS
            result_value = json.dumps((fetched_entities, cookie))
        else:
            status = EXECUTION_STATE_COMPLETED
            result_value = True
            if entities:
                siemplify.result.add_result_json(fetched_entities)
                output_message = 'Successfully performed query {} in Active Directory'.format(query_string)
            else:
                output_message = 'No results to show following the query: {}'.format(query_string)
    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}.".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = "Error executing action {}. Reason: {}".format(SCRIPT_NAME, e)

    siemplify.LOGGER.info('----------------- {} - Finished -----------------'.format(mode))
    siemplify.LOGGER.info(
        "\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == 'True'
    main(is_first_run)
