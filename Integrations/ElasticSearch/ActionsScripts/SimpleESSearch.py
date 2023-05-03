from SiemplifyUtils import output_handler
from ElasticsearchManager import ElasticsearchManager
from SiemplifyAction import SiemplifyAction
from TIPCommon import construct_csv, dict_to_flat
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

    index = siemplify.parameters.get("Index")
    query = siemplify.parameters.get('Query')
    limit = siemplify.parameters.get('Limit')

    results, status, total_hits = elasticsearch_wrapper.simple_es_search(index, query, limit)
    if status:
        output_message = "Query ran successfully {0} hits found".format(len(results))
    else:
        output_message = "ERROR: Query failed to run"

    if results:
        flat_results = []
        for result in results:
            flat_result = dict_to_flat(result)
            flat_results.append(flat_result)

        csv_output = construct_csv(flat_results)
        siemplify.result.add_data_table("Results - Total {}".format(len(results)), csv_output)

    siemplify.result.add_result_json(json.dumps(results))
    siemplify.end(output_message, json.dumps(results))


if __name__ == "__main__":
    main()