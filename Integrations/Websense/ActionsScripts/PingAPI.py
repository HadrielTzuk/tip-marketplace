from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import *
from WebsenseManager import WebsenseAPIManager
from TIPCommon import extract_configuration_param

INTEGRATION_NAME = 'Websense'


@output_handler
def main():
	siemplify = SiemplifyAction()
	conf = siemplify.get_configuration('Websense')
	verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
											 input_type=bool, default_value=False)
	websense_manager = WebsenseAPIManager(conf['ApiRoot'], conf['GatewayUser'], conf['GatewayPassword'], verify_ssl)
	conn = websense_manager.test_connectivity()
	if conn:
		output_message = 'Connection Established'
		result_value = 'true'
	else:
		output_message = 'Error accured'
		result_value = 'False'
	
	siemplify.end(output_message, result_value)
	

if __name__ == "__main__":
	main()
