from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SymantecATPManager import SymantecATPManager
from TIPCommon import construct_csv, dict_to_flat

ATP_PROVIDER = 'SymantecATP'
RESULT_TABLE_NAME = "Command IDs"
ACTION_NAME = "SymantecATP_Events Free Query"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(ATP_PROVIDER)
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")
    verify_ssl = conf.get('Verify SSL', 'false').lower() == 'true'
    atp_manager = SymantecATPManager(conf.get('API Root'), conf.get('Client ID'), conf.get('Client Secret'), verify_ssl)

    result_value = False
    events_amount = 0

    # Parameters.
    query = siemplify.parameters.get('Query')
    limit = int(siemplify.parameters.get('Limit')) if siemplify.parameters.get('Limit') else None

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    try:
        query_result = atp_manager.get_events_free_query(query, limit)

        if query_result:
            events_amount = len(query_result)
            query_result = map(dict_to_flat, query_result)
            csv_result = construct_csv(query_result)
            siemplify.result.add_data_table(u"Events Related to the Query", csv_result)
            result_value = True

    except Exception as err:
        siemplify.LOGGER.error(u"General error performing action {}".format(ACTION_NAME))
        siemplify.LOGGER.exception(err)
        

    if result_value:
        output_message = "Found {0} events for query.".format(len(query_result))
    else:
        output_message = "No events were found for query."

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  events_amount: {}\n output_message: {}".format(events_amount, output_message))
   
    siemplify.end(output_message, events_amount)

if __name__ == "__main__":
    main()
