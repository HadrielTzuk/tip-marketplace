from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyAction()
    priority = siemplify.parameters["Alert Priority"]

    request_dict = {"caseId": siemplify.case_id,
                    "alertIdentifier": siemplify.current_alert.identifier,
                    "alertName": siemplify.current_alert.name,
                    "priority": priority
                    }

    # noinspection PyBroadException
    try:
        address = u"{0}/{1}".format(siemplify.API_ROOT, "external/v1/sdk/UpdateAlertPriority")
        response = siemplify.session.post(address, json=request_dict)
        siemplify.validate_siemplify_error(response)
        output_message = u"The alert priority was set to {}".format(priority)
        is_success = "true"
    except Exception as _:
        output_message = ("This method is supported only in Siemplify versions 5.6 and above, "
                          "please make sure your Siemplify version id 5.6 or higher and try again")
        siemplify.LOGGER.info(output_message)
        is_success = "false"

    siemplify.end(output_message, is_success)


if __name__ == "__main__":
    main()
