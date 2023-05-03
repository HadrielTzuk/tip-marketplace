from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = "DummyJob" # In order to use the SiemplifyLogger, you must assign a name to the script.
    print "Sample output"
    
    if siemplify.parameters.get("Fail", "False").lower() == 'true':
        raise Exception("ERROR")
        
    siemplify.LOGGER.info("Job started") # Logs will be found at C:\Siemplify_Server\Scripting\SiemplifyJob\<"Script_Name">
    # SCRIPT LOGIC HERE:
    siemplify.LOGGER.info("Job Finished")


if __name__ == "__main__":
    main()