from SiemplifyUtils import output_handler
# Imports
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import dict_to_flat, flat_dict_to_csv
from MalShareManager import MalShareManager


@output_handler
def main():
    siemplify = SiemplifyAction()

    # Configuration.
    conf = siemplify.get_configuration('MalShare')
    api_key = conf['Api Key']
    verify_ssl = conf.get('Verify SSL', 'false').lower() == 'true'
    malshare = MalShareManager(api_key, verify_ssl)
    file_path = str(siemplify.parameters.get('File Path'))
    json_results = {}

    hash_info = malshare.upload_and_scan(file_path)
    if hash_info:
        json_results[file_path] = hash_info
        flat_report = dict_to_flat(hash_info)
        csv_output = flat_dict_to_csv(flat_report)
        siemplify.result.add_entity_table('{0} Report'.format(file_path), csv_output)

        output_message = "File {0} submitted successfully.".format(file_path)
        result_value = True
    else:
        output_message = 'Failed to submit successfully.'
        result_value = False

    # add json
    siemplify.result.add_result_json(json_results)
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
