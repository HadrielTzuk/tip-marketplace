from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from CertlyManager import CertlyManager
from SiemplifyAction import SiemplifyAction


@output_handler
def main():
	siemplify = SiemplifyAction()
	conf = siemplify.get_configuration('Certly')
	api_token = conf['Api Token']
	api_url = conf['Api Root']
	certly = CertlyManager(api_token, api_url)
	
	urls_to_enrich = []
	result_value = 'false'
	url_status = {}
	status = ''
	
	for entity in siemplify.target_entities:
		if entity.entity_type == EntityTypes.URL:
			res = certly.get_url_status(entity.identifier)
		else:
			continue
		if res:
			status = res['data'][0]['status']
			entity.additional_properties['Certly_Status'] = status
			entity.is_enriched = True
			urls_to_enrich.append(entity)
		
		url_status.update({entity.identifier: status})
		
		if status == 'malicious':
			result_value = 'true'
			entity.is_suspicious = True
			siemplify.add_entity_insight(entity, 'Found as suspicious by Certly.')
		
	if urls_to_enrich:
		message = "Following Urls were enriched by Certly.\n"
		for identifier, status in url_status.items():
			message += "{0}: Status: {1}\n".format(identifier, status)
		output_message = message
		siemplify.update_entities(urls_to_enrich)
	else:
		output_message = 'No entities were enriched.'

	siemplify.end(output_message, result_value)

if __name__ == "__main__":
	main()