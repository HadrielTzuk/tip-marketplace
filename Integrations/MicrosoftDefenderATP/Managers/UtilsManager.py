import re
from TIPCommon import WHITELIST_FILTER, BLACKLIST_FILTER


UNIX_FORMAT = 1
DATETIME_FORMAT = 2


def pass_whitelist_filter(siemplify, whitelist_as_a_blacklist, model, model_key, whitelist=None):
    # whitelist filter
    whitelist = whitelist or siemplify.whitelist
    whitelist_filter_type = BLACKLIST_FILTER if whitelist_as_a_blacklist else WHITELIST_FILTER
    model_value = getattr(model, model_key)
    model_values = model_value if isinstance(model_value, list) else [model_value]

    if whitelist:
        for value in model_values:
            if whitelist_filter_type == BLACKLIST_FILTER and value in whitelist:
                siemplify.LOGGER.info(u"'{}' did not pass blacklist filter.".format(value))
                return False

            if whitelist_filter_type == WHITELIST_FILTER and value not in whitelist:
                siemplify.LOGGER.info(u"'{}' did not pass whitelist filter.".format(value))
                return False

    return True


def is_valid_domain(domain_name):
    regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
    p = re.compile(regex)

    if domain_name is None:
        return False

    if re.search(p, domain_name):
        return True
    else:
        return False


def get_entity_original_identifier(entity):
    """
    Helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get('OriginalIdentifier', entity.identifier)
