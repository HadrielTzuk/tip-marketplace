from SiemplifyUtils import output_handler
from SiemplifyAction import *

@output_handler
def main():
    siemplify = SiemplifyAction()
    comment = siemplify.parameters["Comment"]
    siemplify.add_comment(comment)

    output_message = "Comment added to case:\n %s" % comment    
    siemplify.end(output_message, "true")

if __name__ == '__main__':
	main()
