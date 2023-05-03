from SiemplifyUtils import output_handler
from SiemplifyAction import *

@output_handler
def main():
    siemplify = SiemplifyAction()
    comment = siemplify.parameters["Instruction"]

    output_message = "Please perform the following instructions:\n %s" % comment    
    siemplify.end(output_message, "true")

if __name__ == '__main__':
    main()
