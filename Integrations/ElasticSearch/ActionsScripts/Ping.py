from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from ElasticsearchManager import ElasticsearchManager
from SiemplifyAction import SiemplifyAction


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
        elasticsearch_wrapper = ElasticsearchManager(server_address, verify_ssl, ca_certificate_file=ca_certificate_file)
    
    connectivity = elasticsearch_wrapper.test_connectivity()
    output_message = "Connected Successfully"

    siemplify.end(output_message, connectivity)
    

if __name__ == "__main__":
    main()
