from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from AlexaManager import AlexaManager
from SiemplifyAction import SiemplifyAction

		
@output_handler
def main():
	siemplify = SiemplifyAction()
	conf = siemplify.get_configuration('Alexa')
	access_key_id = conf['Access key id']
	secret_access_key = conf['Secret access key']
	alexa = AlexaManager(access_key_id, secret_access_key)
	
	connectivity = alexa.test_connectivity()
	output_message = "Connected Successfully"
	siemplify.end(output_message, connectivity)
           

if __name__ == '__main__':
	main()