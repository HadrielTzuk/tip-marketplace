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
	
	for entity in entities:
		# Remove '@' or http 
		domain = dt_manager.extract_domain_from_string(entity.identifier)
		print domain
		try:
			domain_risk = dt_manager.getDomainRisk(domain)
			print domain_risk
		except DomainToolsManagerError:
			continue
		if siemplify.parameters['Threshold'] < domain_risk:
			is_risky = True
			entity.is_suspicious = True
			risky_domains.append(entity)
		
		entity.additional_properties['DT_Risk'] = domain_risk
		enriched_entities.append(entity)

	siemplify.update_entities(enriched_entities)
	if risky_domains:
		output_message = "Following domains found risky By Domain Tools:\n{0}".format("\n".join(map(str, risky_domains)))
	siemplify.end(output_message, is_risky)

if __name__ == "__main__":
	main()