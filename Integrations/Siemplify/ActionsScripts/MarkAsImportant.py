from SiemplifyUtils import output_handler
from SiemplifyAction import *

@output_handler
def main():
    siemplify = SiemplifyAction()
    
    isImportantStatus = siemplify.case.is_important
    if (isImportantStatus):
        output_message = "The case is already important."    
    else:
        siemplify.mark_case_as_important()
        output_message = "The case was automatically marked as important."    
    
    siemplify.end(output_message, "true")

if __name__ == '__main__':
    main()
