import ipaddress

from exceptions import AWSEC2ValidationException


def load_csv_to_list(csv, param_name, delimiter):
    """
    Load delimiter separated values represented as string to a list
    :param csv: {str} of separated values with delimiter
    :param param_name: {str} the name of the variable we are validation
    :param delimiter: {str} According to this delimiter the values will be separated
    :return: {list} of values
            raise AWSEC2ValidationException if failed to parse csv
    """
    try:
        return [t.strip() for t in csv.split(delimiter)]
    except Exception:
        raise AWSEC2ValidationException(f"Failed to parse parameter {param_name}")


def is_tag_key_unique(keys_set: set, key: str):
    """
    Validates if the key is unique
    :param keys_set: {set} set of keys
    :param key: {str} The key to validate
    :return: True if the key does not exists in keys_set
            raise AWSEC2ValidationException if key is not unique
    """
    if key and key in keys_set:
        raise AWSEC2ValidationException(f'Tag keys must be unique per resource.')
    return True


def handle_tags(tags_list: list):
    """
    Returns a list of valid and invalid tags
    :param tags_list: list of input tags. ([tag_name:tag_value,...])
    :return: valid_tags: list of tags ready to be sent in the API call {'Key': key, 'Value': value}
             invalid_tags: list of invalid tags, for example missing ':' tags
             not_unique_tags: list of tags that was not unique in the tags_list
    """
    tags_dict = {}
    not_unique_tags = []
    valid_tags = []
    invalid_tags = []

    for tag in tags_list:
        key_value_tag = tag.split(":")

        # if the tag is not in structure of key:value
        if len(key_value_tag) != 2 or not key_value_tag[0]:
            invalid_tags.append(tag)
            continue

        if not tags_dict.get(key_value_tag[0]):
            tags_dict[key_value_tag[0]] = [key_value_tag[1]]
        else:
            tags_dict[key_value_tag[0]].append(key_value_tag[1])

    for key, value in tags_dict.items():
        if len(value) > 1:
            not_unique_tags.extend([key + ":" + value_t for value_t in value])
        else:
            valid_tags.append({
                'Key': key,
                'Value': value[0]
            })

    return valid_tags, invalid_tags, not_unique_tags


def remove_empty_kwargs(**kwargs) -> dict:
    """
    Remove keys from dictionary that has the value None
    :param kwargs: key value arguments
    :return: {dict} dictionary without keys that have the value None
    """
    return {k: v for k, v in kwargs.items() if v is not None}


def compress_ipv6_address(ipv6: str) -> str:
    """
    Compress ipv6 ip address. IPV6 address must be masked.
    :param ipv6: {Str} IPV6 address to compress
    :return: {str} Compressed IPV6 address. If failed to get ipv6 compressed, return parameter
    """
    try:
        return ipaddress.ip_network(ipv6).compressed
    except Exception:
        return ipv6

