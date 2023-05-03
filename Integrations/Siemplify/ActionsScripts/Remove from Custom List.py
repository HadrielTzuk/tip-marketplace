from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "Remove From Custom List"

    category = siemplify.parameters["Category"]

    if siemplify.is_existing_category(category):
        custom_list_items = siemplify.remove_alert_entities_from_custom_list(category)

        if len(custom_list_items) == 0:
            output_message = u"No entities were removed from custom list category: {0}.".format(
                category)
        else:
            removed_entities = ', '.join(cli.identifier for cli in custom_list_items)
            output_message = u"The alert's entities <{0}> were removed from custom list category: {1}.".format(
                removed_entities, category)
    else:
        output_message = "The given category does not exist."
    siemplify.LOGGER.info(output_message)

    siemplify.end(output_message, "true")


if __name__ == '__main__':
    main()
