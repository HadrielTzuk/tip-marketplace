from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "Is In Custom List"

    category = siemplify.parameters["Category"]

    result_value = siemplify.any_alert_entities_in_custom_list(category)

    if result_value:
        output_message = u"This alert contains entities in the given custom list category: {0}.".format(
            category)
    else:
        output_message = u"This alert does not contain entities in the given custom list category: {0}.".format(
            category)
    siemplify.LOGGER.info(output_message)

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
