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

    status_code, output, error = ssh_wrapper.execute_program(siemplify.parameters['Remote Program Path'])
    if status_code == 0:
        results = 'True'
        output_message = output.read()
    else:
        results = 'False'
        output_message = error.read()
    siemplify.end(output_message, results)


if __name__ == "__main__":
    main()