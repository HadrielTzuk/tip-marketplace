from SiemplifyUtils import output_handler
import json
import logging as log
from requests import HTTPError
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import InsightSeverity, InsightType


@output_handler
def main():
    siemplify = SiemplifyAction()
    title = siemplify.parameters["Title"]
    message = siemplify.parameters["Message"]
    triggered_by = siemplify.parameters.get("Triggered By", "Siemplify System")

    siemplify.create_case_insight(triggered_by=triggered_by,
                                  title=title,
                                  content=message,
                                  entity_identifier="",
                                  severity=InsightSeverity.INFO,
                                  insight_type=InsightType.General)

    output_message = "Added insight with message [%s]" % message

    siemplify.end(output_message, 'true')


if __name__ == '__main__':
    main()