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
    # Should raise exception in case creds are wrong
    sentinel_one_manager = SentinelOneManager(conf['Api Root'], conf['Username'], conf['Password'])

    siemplify.end('Connection Established.', True)


if __name__ == '__main__':
    main()
