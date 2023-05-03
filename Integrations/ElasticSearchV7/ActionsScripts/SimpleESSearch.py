from SiemplifyUtils import output_handler
from ElasticsearchManager import ElasticsearchManager
from SiemplifyAction import SiemplifyAction
from TIPCommon import construct_csv, dict_to_flat, extract_configuration_param, extract_action_param
import json

INTEGRATION_NAME = "ElasticSearchV7"
SCRIPT_NAME = "ElasticSearchV7-SimpleESSearch"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    # Integration Parameters
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Server Address",
                                            is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                            is_mandatory=False)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                            is_mandatory=False)    
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Token",
                                            is_mandatory=False)   
    authenticate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Authenticate",
                                            is_mandatory=True, default_value=False, input_type=bool)        
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                            is_mandatory=True, default_value=False, input_type=bool)
    ca_certificate_file = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="CA Certificate File",
                                            is_mandatory=False, input_type=str)
    if authenticate:
        elasticsearch_wrapper = ElasticsearchManager(server_address, username=username, password=password, api_token=api_token, verify_ssl=verify_ssl, authenticate=True, ca_certificate_file=ca_certificate_file) 
    else:
        elasticsearch_wrapper = ElasticsearchManager(server_address, verify_ssl=verify_ssl, ca_certificate_file=ca_certificate_file)

    index = siemplify.parameters.get("Index")
    query = siemplify.parameters.get('Query')
    limit = siemplify.parameters.get('Limit')

    results, status, total_hits = elasticsearch_wrapper.simple_es_search(index, query, limit)
    if status:
        output_message = "Query ran successfully {0} hits found".format(len(results))
    else:
        output_message = "ERROR: Query failed to run"

    if results:
        flat_results = []
        for result in results:
            flat_result = dict_to_flat(result)
            flat_results.append(flat_result)

        csv_output = construct_csv(flat_results)
        siemplify.result.add_data_table("Results - Total {}".format(len(results)), csv_output)

    siemplify.result.add_result_json(json.dumps(results))
    siemplify.end(output_message, json.dumps(results))


if __name__ == "__main__":
    main()