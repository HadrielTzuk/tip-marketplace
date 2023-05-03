

def safe_str_cast(data, default_value=None, current_encoding='utf-8', target_encoding='utf-8', convert_none=False):
    """
    :param data: {Input} Cam be string, unicode or object.
    :param default_value: {str} Default value return on error.
    :param current_encoding: {str} Current value encoding - Relevant for STR data.
    :param target_encoding: {str} Target
    :param convert_none: {bool}
    :return:
    """
    try:
        if not convert_none and data is None:
            return None
        elif isinstance(data, unicode):
            return data.encode(target_encoding)
        elif isinstance(data, str):
            return data.decode(current_encoding).encode(target_encoding)
        else:
            return unicode(data).encode(target_encoding)
    except:
        if default_value:
            return default_value
        raise Exception("Failed casting received data to string.")
