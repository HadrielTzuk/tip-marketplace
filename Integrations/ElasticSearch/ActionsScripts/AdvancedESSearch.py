from SiemplifyUtils import output_handler
from ElasticsearchManager import ElasticsearchManager
from SiemplifyAction import SiemplifyAction
from TIPCommon import dict_to_flat, construct_csv
import json


@output_handler
def main():
    siemplify = SiemplifyAction()

    conf = siemplify.get_configuration('ElasticSearch')
    server_address = conf['Server Address']
    username = conf['Username']
    password = conf['Password']
    ca_certificate_file = conf['CA Certificate File']
    authenticate = conf['Authenticate'].lower() == 'true'
    verify_ssl = conf['Verify SSL'].lower() == 'true'

    if authenticate:
        elasticsearch_wrapper = ElasticsearchManager(server_address, username,
                                                     password, verify_ssl=verify_ssl, ca_certificate_file=ca_certificate_file)
    else:
        elasticsearch_wrapper = ElasticsearchManager(server_address, verify_ssl=verify_ssl, ca_certificate_file=ca_certificate_file)

    kwargs = {}

    kwargs['Index'] = siemplify.parameters.get("Index")
    kwargs['Query'] = siemplify.parameters.get('Query')
    kwargs['Display Field'] = siemplify.parameters.get('Display Field')
    kwargs['Search Field'] = siemplify.parameters.get('Search Field')
    kwargs['Timestamp Field'] = siemplify.parameters.get('Timestamp Field')
    kwargs['Oldest Date'] = siemplify.parameters.get('Oldest Date')
    kwargs['Earliest Date'] = siemplify.parameters.get('Earliest Date')
    kwargs['Limit'] = siemplify.parameters.get('Limit')
    kwargs['Oldest Date Compare Type'] = 'gte'
    kwargs['Earliest Date Compare Type'] = 'lte'

    results, status, total_hits = elasticsearch_wrapper.advanced_es_search(**kwargs)

    if status or results:
        output_message = "Query ran successfully {0} hits found".format(len(results)) if results else \
            "No results found for the provided query."
    else:
        output_message = "ERROR: Query failed to run"

    if results:
        flat_results = []
        for result in results:
            flat_result = dict_to_flat(result)
            flat_results.append(flat_result)

        csv_output = construct_csv(flat_results)
        siemplify.result.add_data_table("Results - Total {}".format(len(results)),
                                        csv_output)

    siemplify.result.add_result_json(json.dumps(results))
    siemplify.end(output_message, json.dumps(results))


if __name__ == "__main__":
    main()