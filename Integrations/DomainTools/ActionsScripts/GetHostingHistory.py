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
	risky_domains = []
	is_risky = False
	output_message = "No Risky domain were found"
	domain_hosting_history = None
	for entity in entities:
		# Remove '@' or http 
		domain = dt_manager.extract_domain_from_string(entity.identifier)
		print domain
		try:
			domain_hosting_history = dt_manager.getHostingHistory(domain)
			print domain_hosting_history
			if domain_hosting_history:
				# Flat the dict
				domain_hosting_history = dict_to_flat(domain_hosting_history)
				csv_output = flat_dict_to_csv(domain_hosting_history)
				# Add prefix to dict
				domain_hosting_history = add_prefix_to_dict_keys(domain_hosting_history, "DT")
				siemplify.result.add_entity_table(entity.identifier, csv_output)
				entity.additional_properties.update(domain_hosting_history)
				enriched_entities.append(entity)
		except DomainToolsManagerError:
			continue		
			
	if domain_hosting_history:
		output_message = "Domains Hosting History attached to results"
	siemplify.end(output_message, is_risky)

if __name__ == "__main__":
	main()