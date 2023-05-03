from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from constants import INTEGRATION_NAME, RUN_WQL_QUERY_ACTION
from TIPCommon import extract_configuration_param, construct_csv, extract_action_param
from SCCMManager import SCCMManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from exceptions import QueryException
import base64
import json

# Constants
TABLE_HEADER = "WQL Query results Columns"
ATTACHED_FILE_TITLE = 'Attached Result File.'
RESULT_FILE_NAME_FORMAT = 'Run_WQL_query_response.json'

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = RUN_WQL_QUERY_ACTION
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Init Integration Configurations
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Server Address",
                                                 is_mandatory=True)
    domain = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Domain",
                                         is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)

    # Init Action Parameters
    query = extract_action_param(siemplify, param_name='Query to run', is_mandatory=True, print_value=True)
    max_records_to_return = extract_action_param(siemplify, param_name='Number of records to return', is_mandatory=True,
                                                 input_type=int)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    try:
        manager = SCCMManager(server_address, domain, username, password)
        results = manager.run_wql_query(query)

        if results:
            output_message = "Query executed successfully and returned results."

            if len(results) > max_records_to_return:
                results = results[:max_records_to_return]
                output_message += "\nQuery results exceeded limits and were truncated!"

            json_results = [result.to_json() for result in results]
            siemplify.result.add_result_json(json_results)
            siemplify.result.add_entity_table(TABLE_HEADER, construct_csv([result.to_table() for result in results]))
            # Add results file to action result.
            base64_content = base64.b64encode(json.dumps(json_results).encode()).decode()
            siemplify.result.add_entity_attachment(ATTACHED_FILE_TITLE, RESULT_FILE_NAME_FORMAT, base64_content)
        else:
            output_message = "Query executed successfully, but did not return any results."

    except QueryException as e:
        result_value = False
        output_message = "Query didn't complete due to error: {}".format(e)
    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}. Error: {}".format(RUN_WQL_QUERY_ACTION, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = "Failed to connect to the Microsoft SCCM instance! Error is {}".format(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        "Status: {}, Result Value: {}, Output Message: {}"
        .format(status, result_value, output_message)
    )

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
