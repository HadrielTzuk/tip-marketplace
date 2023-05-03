from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler
from TestManager1 import TestManager1
from TestManager2 import TestManager2
import subprocess
import pyjokes
import cowsay


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = "DummyJob" # In order to use the SiemplifyLogger, you must assign a name to the script.
    
    t1 = TestManager1()
    assert t1.get_version() == "A1"

    t2 = TestManager2()
    assert t2.get_version() == "A2"

    cowsay.cheese("YAY")
    pyjokes.get_joke()

    assert pyjokes.__version__ == "0.5.0"
    proc = subprocess.Popen("pip freeze", stdout=subprocess.PIPE, shell=True)
    out, err = proc.communicate()
    assert "cowsay==2.0.3" in out
        
    siemplify.LOGGER.info("Job started") # Logs will be found at C:\Siemplify_Server\Scripting\SiemplifyJob\<"Script_Name">
    # SCRIPT LOGIC HERE:
    siemplify.LOGGER.info("Job Finished")

if __name__ == "__main__":
    main()