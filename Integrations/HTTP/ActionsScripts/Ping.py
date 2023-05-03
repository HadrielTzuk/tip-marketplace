from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction

		
@output_handler
def main():
	siemplify = SiemplifyAction()
	output_message = "Connected Successfully"
	siemplify.end(output_message, 'true')
           

if __name__ == '__main__':
	main()