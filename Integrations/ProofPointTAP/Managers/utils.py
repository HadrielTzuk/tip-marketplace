def validate_positive_integer(number, err_msg="Limit parameter should be positive"):
    if number <= 0:
        raise Exception(err_msg)


def get_entity_original_identifier(entity):
    """
    Helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get('OriginalIdentifier', entity.identifier)