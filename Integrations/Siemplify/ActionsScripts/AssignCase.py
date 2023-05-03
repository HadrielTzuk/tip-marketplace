from SiemplifyUtils import output_handler
from SiemplifyAction import *

@output_handler
def main():
    siemplify = SiemplifyAction()
    assigned_user = siemplify.parameters["Assigned User"]
    
    siemplify.assign_case(assigned_user)

    output_message = "The case was successfully assigned to %s." %assigned_user.strip("@")
    
    siemplify.end(output_message, "true")

if __name__ == '__main__':
	main()
