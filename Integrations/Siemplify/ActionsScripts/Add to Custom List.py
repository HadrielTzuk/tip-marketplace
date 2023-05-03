from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "Add To Custom List"

    category = siemplify.parameters["Category"]

    custom_list_items = siemplify.add_alert_entities_to_custom_list(category)

    if len(custom_list_items) == 0:
        output_message = u"No entities were added to custom list category: {0}.".format(category)
    else:
        added_entities = ', '.join(cli.identifier for cli in custom_list_items)
        output_message = u"The alert's entities <{0}> were added to custom list category: {1}.".format(added_entities,
                                                                                                       category)

    siemplify.LOGGER.info(output_message)

    siemplify.end(output_message, "true")


if __name__ == '__main__':
    main()