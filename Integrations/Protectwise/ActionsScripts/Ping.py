from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from ProtectwiseManager import ProtectwiseManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    configurations = siemplify.get_configuration('Protectwise')
    username = configurations['Email']
    password = configurations['Password']

    # If no exception occurs - then connection is successfull
    protectwise_manager = ProtectwiseManager(username, password)

    siemplify.end("Connected successfully.", 'true')


if __name__ == '__main__':
    main()