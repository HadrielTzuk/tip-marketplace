from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from DomainToolsManager import DomainToolsManager, DomainToolsManagerError
from SiemplifyUtils import *

URL = EntityTypes.URL
HOST = EntityTypes.HOSTNAME

@output_handler
def main():
	siemplify = SiemplifyAction()
	conf = siemplify.get_configuration('DomainTools')
	username = conf['Username']
	key = conf['ApiToken']
	dt_manager = DomainToolsManager(username, key)

	entities = [entity for entity in siemplify.target_entities if (entity.entity_type==URL or entity.entity_type==HOST) 
				and not entity.is_internal]
	enriched_entities = []
	
	for entity in entities:
		# Remove '@' or http 
		domain = dt_manager.extract_domain_from_string(entity.identifier)
		try:
			domain_profile = dt_manager.getDomainProfile(domain)
			print domain_profile
		except DomainToolsManagerError:
			continue
			
		# Flat the dict
		if domain_profile: 
			domain_profile = dict_to_flat(domain_profile)
			csv_output = flat_dict_to_csv(domain_profile)
			# Add prefix to dict
			domain_profile = add_prefix_to_dict_keys(domain_profile, "DT")
		
			siemplify.result.add_entity_table(entity.identifier, csv_output)
			entity.additional_properties.update(domain_profile)
			enriched_entities.append(entity)

	if enriched_entities:
		siemplify.update_entities(enriched_entities)
		output_message = "Entities Enriched By Domain Tools:\n{0}".format("\n".join(map(str, enriched_entities)))
		result_value = 'true'

	else:
		output_message = 'No entities were enriched.'

	siemplify.end(output_message, result_value)

if __name__ == "__main__":
	main()