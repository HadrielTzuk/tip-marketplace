from SiemplifyUtils import output_handler
from SiemplifyAction import *

@output_handler
def main():
    siemplify = SiemplifyAction()
    tag = siemplify.parameters["Tag"]
    siemplify.add_tag(tag)

    output_message = "The tag [%s] was added to the case" % tag    
    siemplify.end(output_message, "true")

if __name__ == '__main__':
	main()
