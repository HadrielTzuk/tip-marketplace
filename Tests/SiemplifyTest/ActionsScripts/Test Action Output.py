from SiemplifyUtils import output_handler
from SiemplifyAction import *
from SiemplifyUtils import flat_dict_to_csv
from base64 import b64encode
import json

ACTION_NAME = "SiemplifyTest_TesOutput"

HTML_REPORT = "<html><body><div>{0}</div></body>></html>"

URL = "https://wwww.google.com"

RECORD_AMOUNT = 1000


def create_dummy_file(path):
    """
    Creates and returns demmy file path and base64 content.
    :param path: {string} Directory to create file.
    :return: {string} Dummy file path.
    """
    file_path = "{0}/DummyFile.txt".format(path)
    file_content = "Dummy Test"
    with open(file_path, 'a+') as f:
        f.write(file_content)
    return file_path


def build_large_dummy_json(records_amount):
    result_json = {}
    for i in range(records_amount):
        record = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa {0} bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        result_json[record.format(i)] = record.format(i)
    return result_json


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    dummy_file_path = create_dummy_file(siemplify.run_folder)
    dummy_json = build_large_dummy_json(RECORD_AMOUNT)

    print "Action started"
    for entity in siemplify.target_entities:
        siemplify.add_entity_insight(entity, "Insight for: {0}".format(entity.identifier))
        siemplify.add_comment("Comment for: {0}".format(entity.identifier))
        siemplify.add_attachment(dummy_file_path)
        # Results.
        siemplify.result.add_entity_html_report(entity.identifier, "HTML for: {0}".format(entity.identifier),
                                                HTML_REPORT.format(entity.identifier))
        siemplify.result.add_entity_attachment(entity.identifier, "Attachment for: {0}".format(entity.identifier),
                                               b64encode("Dummy Content"))
        siemplify.result.add_content(entity.identifier, "Content for: {0}".format(entity.identifier))
        siemplify.result.add_entity_link(entity.identifier, URL)
        siemplify.result.add_entity_json(entity.identifier, json.dumps(dummy_json))
        siemplify.result.add_entity_table(entity.identifier, flat_dict_to_csv(dummy_json))
        siemplify.result.add_result_json(dummy_json)
    output_message = 'output message'
    result_value = 'true'
    print "Action done"
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()