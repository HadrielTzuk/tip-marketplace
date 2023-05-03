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
				
	output_message = "Connection Establishe" if dt_manager else "Connection Failed"
	siemplify.end(output_message, 'true')

if __name__ == "__main__":
	main()