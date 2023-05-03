from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
# Imports
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import dict_to_flat, flat_dict_to_csv
from A1000MalwareAnalysis import A1000MalwareAnalysisClient


@output_handler
def main():
    siemplify = SiemplifyAction()

    # Configuration.
    conf = siemplify.get_configuration("ReversinglabsA1000")
    server_address = conf['Api Root']
    username = conf['Username']
    password = conf['Password']

    a1000_manager = A1000MalwareAnalysisClient(server_address, username, password)

    file_path = siemplify.parameters['File Path']

    upload_result = a1000_manager.upload_file(file_path)

    # Wait for results
    while a1000_manager.processing_status([upload_result['sha1']])[0]['status'] != 'processed':
        pass
    result = a1000_manager.get_report([upload_result['sha1']])

    json_results = {}
    if result:
        result = result[0]
        json_results = result
        # Take the first record, only one record will be included
        flat_report = dict_to_flat(result)
        csv_output = flat_dict_to_csv(flat_report)
        siemplify.result.add_data_table('File Details:', csv_output)
        output_message = "File {0} successfully uploaded to A1000.".format(file_path)
        result_value = True
    else:
        output_message = 'Failed to upload file {0} to A1000.'.format(file_path)
        result_value = False

    # add json
    siemplify.result.add_result_json(json_results)

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
