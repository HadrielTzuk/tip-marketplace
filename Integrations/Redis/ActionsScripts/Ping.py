from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from RedisManager import RedisManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('Redis')
    server = conf['Server Address']
    port = int(conf['Port'])
    redis_manager = RedisManager(server, port, 0)

    # Check if the connection is established or not.
    redis_manager.test_connectivity()

    # If no exception occur - then connection is successful
    output_message = "Successfully connected to Redis at {server_addr}:{port}.".format(server_addr=server, port=port)
    siemplify.end(output_message, True)


if __name__ == '__main__':
    main()
