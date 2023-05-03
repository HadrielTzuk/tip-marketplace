from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from ElasticsearchManager import ElasticsearchManager
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param

INTEGRATION_NAME = "ElasticSearchV7"
SCRIPT_NAME = "ElasticSearchV7-Ping"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
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
        elasticsearch_wrapper = ElasticsearchManager(server_address, username=username, password=password, api_token=api_token, verify_ssl=verify_ssl, ca_certificate_file=ca_certificate_file, authenticate=True) 
    else:
        elasticsearch_wrapper = ElasticsearchManager(server_address, verify_ssl, ca_certificate_file=ca_certificate_file)

    connectivity = elasticsearch_wrapper.test_connectivity()
    output_message = "Connected Successfully"

    siemplify.end(output_message, connectivity)
    

if __name__ == "__main__":
    main()
