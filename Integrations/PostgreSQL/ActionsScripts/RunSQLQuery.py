from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from PostgreSQLManager import PostgreSQLManager, PostgreSQLException
import json
import datetime

PROVIDER_NAME = u'PostgreSQL'
SCRIPT_NAME = u'{} - Run SQL Query'.format(PROVIDER_NAME)

def datetime_handler(x):
    if isinstance(x, datetime.datetime):
        return x.isoformat()


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration(PROVIDER_NAME)

    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")
    server_addr = conf["Server Address"]
    username = conf["Username"]
    password = conf["Password"]
    port = conf.get("Port")

    database = siemplify.parameters["Database Name"]
    query = siemplify.parameters["Query"]

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    try:
        postgres_manager = PostgreSQLManager(username=username,
                                             password=password,
                                             server=server_addr,
                                             database=database,
                                             port=port)

        # Run search query
        results = postgres_manager.execute(query) or []
        # Close the connection
        postgres_manager.close()

        if results:
            # Construct csv
            csv_output = postgres_manager.construct_csv(results)
            siemplify.result.add_data_table("PostgreSQL Query Results", csv_output)

        siemplify.result.add_result_json(json.dumps(results, default=datetime_handler))
        siemplify.end("Successfully finished search. Found {} rows.".format(len(results)), json.dumps(results, default=datetime_handler))
    except (PostgreSQLException, Exception) as e:
        e = unicode(e)
        output_message = u'Failed to execute query. Error: {}'.format(e)
        result = u'false'
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        siemplify.end(output_message, result, status)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")


if __name__ == "__main__":
    main()

