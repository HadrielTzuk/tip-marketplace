from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SentinelOneManager import SentinelOneManager


# Consts.
SENTINEL_ONE_PROVIDER = 'SentinelOne'


@output_handler
def main():
    # Configuration.
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration(SENTINEL_ONE_PROVIDER)
    sentinel_one_manager = SentinelOneManager(conf['Api Root'], conf['Username'], conf['Password'])

    # Get system status.
    system_version = sentinel_one_manager.get_system_version()

    # Form output message.
    output_message = 'System version is: {0}'.format(system_version)

    siemplify.end(output_message, True)


if __name__ == '__main__':
    main()
