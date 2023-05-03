from SiemplifyUtils import output_handler
from SiemplifyAction import *

@output_handler
def main():
    siemplify = SiemplifyAction()
    
    workflow_name = siemplify.parameters["Playbook Name"]
    success = siemplify.attach_workflow_to_case(workflow_name)
    if (str(success) == "True"):
    	output_message = "Attached Playbook [%s] to Case [%s], Alert [%s]" % (workflow_name,siemplify.case_id,siemplify.current_alert.identifier)
    else:
    	output_message = "Failed to attach Playbook [%s] to Case [%s], Alert [%s]" % (workflow_name,siemplify.case_id,siemplify.current_alert.identifier)
    
    siemplify.end(output_message, str(success))

if __name__ == '__main__':
    main()
