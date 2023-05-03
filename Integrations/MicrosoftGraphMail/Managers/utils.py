import os

from constants import PLACEHOLDER_START, PLACEHOLDER_END
from base64 import b64encode
from SiemplifyDataModel import Attachment


def transform_dict_keys(original_dict, prefix, suffix=None, keys_to_except=tuple()):
    """
    Transform dict keys by adding prefix and suffix
    :param original_dict: {dict} Dict to transform keys
    :param prefix: {str} Prefix for the keys
    :param suffix: {str} Suffix for the keys
    :param keys_to_except: {list} The list of keys which shouldn't be transformed
    :return: {dict} The transformed dict
    """
    if prefix and suffix:
        return {f"{prefix}_{key}_{suffix}" if key not in keys_to_except else key: value
                for key, value in original_dict.items()}
    elif prefix:
        return {f"{prefix}_{key}" if key not in keys_to_except else key: value for key, value in original_dict.items()}

    return original_dict


def transform_template_string(template, event):
    """
    Transform string containing template using event data
    :param template: {str} String containing template
    :param event: {dict} Case event
    :return: {str} Transformed string
    """
    index = 0

    while PLACEHOLDER_START in template[index:] and PLACEHOLDER_END in template[index:]:
        partial_template = template[index:]
        start, end = partial_template.find(PLACEHOLDER_START) + len(PLACEHOLDER_START),\
                     partial_template.find(PLACEHOLDER_END)
        substring = partial_template[start:end]
        value = event.get(substring) if event.get(substring) else ""
        template = template.replace(f"{PLACEHOLDER_START}{substring}{PLACEHOLDER_END}", value, 1)
        index = index + start + len(value)

    return template


def create_siemplify_case_wall_attachment_object(full_file_name: str,
                                                 file_contents: bytes) -> Attachment:
    """
    Create attachment object with the original email
    :param full_file_name: {string} File name of the attachment
    :param file_contents: {string} Attachment content as a string
    :return: {Attachment} of attachment object
    """
    base64_blob = b64encode(file_contents).decode()

    file_name, file_extension = os.path.splitext(full_file_name)
    attachment_object = Attachment(
        case_identifier=None,
        alert_identifier=None,
        base64_blob=base64_blob,
        attachment_type=file_extension,
        name=file_name,
        description="Original email attachment",
        is_favorite=False,
        orig_size=len(file_contents),
        size=len(base64_blob))
    return attachment_object
