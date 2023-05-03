from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from PostgreSQLManager import PostgreSQLManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('PostgreSQL')
    server_addr = conf["Server Address"]
    username = conf["Username"]
    password = conf["Password"]
    port = conf.get("Port")
    database = conf.get("Database Name For Testing")

    postgres_manager = PostgreSQLManager(username=username,
                               password=password,
                               server=server_addr,
                               database=database,
                               port=port)

    postgres_manager.close()

    # If no exception occur - then connection is successful
    output_message = "Successfully connected to {database} at {server_addr}:{port}.".format(
        server_addr=server_addr,
        database=database,
        port=port
    )
    siemplify.end(output_message, True)


if __name__ == '__main__':
    main()
