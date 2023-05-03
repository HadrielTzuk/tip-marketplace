from SiemplifyUtils import output_handler
from SiemplifyAction import *

@output_handler
def main():
	siemplify = SiemplifyAction()
	
	caseStatus = siemplify.case.status 
	StatusResult = None
	
	if (caseStatus != 1):
		output_message = "Cannot close case, as it is already not opened."
		StatusResult = "False"
	else:
		root_cause = siemplify.parameters["Root Cause"]
		comment = siemplify.parameters["Comment"]
		reason = siemplify.parameters["Reason"]
		siemplify.close_case(root_cause,comment,reason)
		StatusResult = "True"
		
		output_message = "The case was closed. \n Root Cause: %s \n Comment: %s \n Reason: %s" % (root_cause,comment,reason)	
	siemplify.end(output_message, StatusResult)

if __name__ == '__main__':
	main()
