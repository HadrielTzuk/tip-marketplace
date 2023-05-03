from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import *
from WebsenseManager import WebsenseAPIManager
from TIPCommon import extract_configuration_param

INTEGRATION_NAME = 'Websense'


@output_handler
def main():
	siemplify = SiemplifyAction()
	output_message = 'Error accured'
	result_value = 'False'
	conf = siemplify.get_configuration('Websense')
	verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
											 input_type=bool, default_value=False)
	websense_manager = WebsenseAPIManager(conf['ApiRoot'], conf['GatewayUser'], conf['GatewayPassword'], verify_ssl)
	category = siemplify.parameters['CategoryName']
	urls = websense_manager.get_category_urls_list(category)

	csv_results = urls
	csv_results.insert(0, "URLs")
	
	siemplify.result.add_data_table("Siemplify Websense Category URls", csv_results)

	output_message = 'Urls list added to result'
	result_value = 'true'
	
	siemplify.end(output_message, result_value)
	

if __name__ == "__main__":
	main()
