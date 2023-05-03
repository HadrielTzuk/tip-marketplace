from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction

@output_handler
def main():
	siemplify = SiemplifyAction()

	output_message = 'Connection Established'
	result_value = 'true'
	siemplify.end(output_message, result_value)

if __name__ == "__main__":
	main()