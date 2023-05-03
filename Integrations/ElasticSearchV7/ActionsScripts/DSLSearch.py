from SiemplifyUtils import output_handler
from ElasticsearchManager import ElasticsearchManager
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv, dict_to_flat
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
import json

INTEGRATION_NAME = "ElasticSearchV7"
SCRIPT_NAME = "DSL Search"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)

    conf = siemplify.get_configuration('ElasticSearchV7')
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Server Address",
                                is_mandatory=True, input_type=str)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=False, input_type=str)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=False, input_type=str)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Token",
                                            is_mandatory=False)   
    authenticate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Authenticate",
                                             default_value=False, input_type=bool)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)
    ca_certificate_file = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="CA Certificate File",
                                            is_mandatory=False, input_type=str)
    
    index = extract_action_param(siemplify, param_name="Index", is_mandatory=False, print_value=True, input_type=str)
    query = extract_action_param(siemplify, param_name="Query", is_mandatory=False, print_value=True, input_type=str)
    limit = extract_action_param(siemplify, param_name="Limit", is_mandatory=False, print_value=True, input_type=int)
    status = EXECUTION_STATE_COMPLETED
    
    try:
        if authenticate:
            elasticsearch_wrapper = ElasticsearchManager(server_address, username=username, password=password, api_token=api_token, verify_ssl=verify_ssl, authenticate=True, ca_certificate_file=ca_certificate_file) 
        else:
            elasticsearch_wrapper = ElasticsearchManager(server_address, verify_ssl=verify_ssl, ca_certificate_file=ca_certificate_file)
        results, total_hits = elasticsearch_wrapper.dsl_search(index, query, limit)
        if results:
            output_message = "Successfully executed ElasticSearch DSL Query {0} hits found".format(len(results))
        else:
            output_message = "Error executing ElasticSearch action 'Run DSL Query'."

        if results:
            flat_results = []
            for result in results:
                flat_result = dict_to_flat(result)
                flat_results.append(flat_result)

            csv_output = construct_csv(flat_results)
            siemplify.result.add_data_table("Results - Total {}".format(len(results)), csv_output)

        siemplify.result.add_result_json(json.dumps(results))
        result = 'true'

    except Exception as e:
        output_message = 'Failed to run DSL query. Error {}'.format(e)
        result = 'false'
        status = EXECUTION_STATE_FAILED

        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()