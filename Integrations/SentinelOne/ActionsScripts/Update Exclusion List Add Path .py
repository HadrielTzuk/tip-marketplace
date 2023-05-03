from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SentinelOneManager import SentinelOneManager


# Consts.
SENTIAL_ONE_PROVIDER = 'SentinelOne'


@output_handler
def main():
    # Configuration.
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration(SENTIAL_ONE_PROVIDER)
    sentinel_one_manager = SentinelOneManager(conf['Api Root'], conf['Username'], conf['Password'])

    # Parameters.
    list_name = siemplify.parameters['List Name']
    file_directory = siemplify.parameters['Path']
    operation_system = siemplify.parameters['Operation System']

    # Get system status.
    sentinel_one_manager.create_path_in_exclusion_list(list_name, file_directory, operation_system)

    # Form output message.
    output_message = 'Directory {0} added to exclusion list {1}'.format(list_name, file_directory)

    siemplify.end(output_message, True)


if __name__ == '__main__':
    main()
