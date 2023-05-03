from SiemplifyUtils import output_handler
import json
import logging as log
from requests import HTTPError
from SiemplifyAction import *

@output_handler
def main():
    siemplify = SiemplifyAction()
    previousPriority = siemplify.case.priority
    
    priority = siemplify.parameters["Priority"]
    
    #print previousPriority
    #print priority
	#
    #if (previousPriority == priority):
    #	output_message = "Case priority change was attempted unsuccessfully, because the case is allready assigned to priority %s." % (priority)
    #else:
    #	siemplify.change_case_priority(priority)
    #	output_message = "Case priority was successfully changed to %s." % (priority)
    
    siemplify.change_case_priority(priority)
    output_message = "Case priority was successfully changed to %s." % (priority)

    output_message = "The case priority was set to %s." % priority
    siemplify.end(output_message, 'true')

if __name__ == '__main__':
	main()
