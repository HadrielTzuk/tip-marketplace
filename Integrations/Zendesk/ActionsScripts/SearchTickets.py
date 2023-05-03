from SiemplifyUtils import output_handler
# Imports
from SiemplifyAction import SiemplifyAction
from ZendeskManager import ZendeskManager
import json

NO_RESULTS = 0


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration("Zendesk")
    user_email = conf['User Email Address']
    api_token = conf['Api Token']
    server_address = conf['Server Address']
    zendesk = ZendeskManager(user_email, api_token, server_address)

    query = siemplify.parameters['Search Query']
    search_result = zendesk.search_tickets(query)

    if search_result['count'] != NO_RESULTS:
        results = search_result['results']
        for result in results:
            result_json = json.dumps(result, indent=4, sort_keys=True)
            siemplify.result.add_json("Ticket - {0}".format(result['id']), result_json)

        output_message = "Successfully found {0} results for {1} search query.".format(search_result['count'], query)
        result_value = search_result['count']
    else:
        output_message = 'Can not find results for {0} search query.'.format(query)
        result_value = NO_RESULTS

    siemplify.result.add_result_json(search_result)
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
