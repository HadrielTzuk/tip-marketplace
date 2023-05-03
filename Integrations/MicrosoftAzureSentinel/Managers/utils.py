from constants import (
    SPECIAL_CHARACTERS_MAPPING,
    PLACEHOLDER_START,
    PLACEHOLDER_END,
    CHARACTERS_LIMIT,
)


class LOGGER(object):
    def __init__(self, logger):
        self.logger = logger

    def info(self, msg):
        if self.logger:
            self.logger.info(msg)

    def error(self, msg):
        if self.logger:
            self.logger.error(msg)

    def exception(self, msg):
        if self.logger:
            self.logger.exception(msg)


def string_to_multi_value(string_value, delimiter=',', only_unique=False):
    # type: (str, str, bool) -> list
    """
    String to multi value.
    @param string_value: {str} String value to convert multi value.
    @param delimiter: {str} Delimiter to extract multi values from single value string.
    @param only_unique: {bool} include only uniq values
    """
    if not string_value:
        return []
    values = [single_value.strip() for single_value in string_value.split(delimiter) if single_value.strip()]
    if only_unique:
        seen = set()
        return [value for value in values if not (value in seen or seen.add(value))]
    return values


def convert_list_to_comma_separated_string(iterable):
    # type: (list or set) -> str
    """
    Convert list to comma separated string
    @param iterable: List or Set to covert
    """
    return ', '.join(iterable)


def convert_list_to_comma_string(value_list, delimiter=', '):
    if not value_list:
        return ''

    return delimiter.join(value_list) if isinstance(value_list, list) else value_list


def handle_special_characters(string):
    """
    Replace special characters in string
    :param string: {str} string to transform
    :return {str} transformed string
    """
    for key, value in SPECIAL_CHARACTERS_MAPPING.items():
        string.replace(key, value)

    return string


def transform_template_string(template, data):
    """
    Transform string containing template using provided data
    :param template: {str} string containing template
    :param data: {dict} data to use for transformation
    :return: {str} transformed string
    """
    index = 0

    while PLACEHOLDER_START in template[index:] and PLACEHOLDER_END in template[index:]:
        partial_template = template[index:]
        start, end = (
            partial_template.find(PLACEHOLDER_START) + len(PLACEHOLDER_START),
            partial_template.find(PLACEHOLDER_END)
        )
        substring = partial_template[start:end]
        value = data.get(substring) if data.get(substring) else ""
        if type(value) in [str, int, float]:
            value = str(value)
        template = template.replace(f"{PLACEHOLDER_START}{substring}{PLACEHOLDER_END}", value, 1)
        index = index + start + len(value)

    return template


def get_value_from_template(template, data, default_value, char_limit = CHARACTERS_LIMIT):
    """
    This method gets a value from a template and data
    :param template: {str} The template to get the value from
    :param data: {dict} The data to get the value from
    :param default_value: {str} The default value to return if the value is not found
    :param char_limit: {int} The maximum length of the value
    :return: {str} The value
    """
    value = (
        transform_template_string(template, data)
        if template
        else default_value
    )
    return value[:char_limit]


def find_fallback_value(source_dicts, fallbacks_list):
    """
    This method is used to get fallback value from list of dicts
    :param source_dicts: List[Dict] List of dicts sorted by priority to extract fallback data from
    :param fallbacks_list: List[str] List of field sorted by priority with keys for extraction
    """
    for item in fallbacks_list:
        for source_dict in source_dicts:
            if item in source_dict:
                return source_dict[item], item
    return None, None

