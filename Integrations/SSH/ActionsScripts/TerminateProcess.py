from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import *
from SshManager import SshManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    server = siemplify.parameters.get('Remote Server')
    username = siemplify.parameters.get('Remote Username')
    password = siemplify.parameters.get('Remote Password')
    port = int(siemplify.parameters.get('Remote Port')) if siemplify.parameters.get('Remote Port') else 22
    ssh_wrapper = SshManager(server, username, password, port)
                            
    process = siemplify.parameters['Process']
    status_code = ssh_wrapper.terminate_process(process)
    if status_code == 0:
        results = 'True'
        output_message = "Successfully Terminated Process ID: {0}".format(process)
    else:
        results = 'False'
        output_message = "Failed to Terminated Process ID: {0}".format(process)
    siemplify.end(output_message, results)


if __name__ == "__main__":
    main()