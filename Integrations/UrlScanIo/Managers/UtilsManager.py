import base64
import tldextract
from datetime import datetime, timezone

def get_entity_original_identifier(entity):
    """
    Helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get('OriginalIdentifier', entity.identifier)


def get_screenshot_content_base64(content):
    """
    Get image base64 encoded by image content
    :param content: {str} Image src
    :return: {bytes} base64 string
    """
    return base64.b64encode(content)


def get_domain_from_entity(identifier):
    """
    Extract domain from entity identifier
    :param identifier: {str} the identifier of the entity
    :return: {str} domain part from entity identifier
    """
    if "@" in identifier:
        return identifier.split("@", 1)[-1]
    try:
        result = tldextract.extract(identifier)
        if result.suffix:
            return ".".join([result.domain, result.suffix])
        return result.domain
    except ImportError:
        raise ImportError("tldextract is not installed. Use pip and install it.")

def timestamp_to_iso(timestamp):
    """
    Function that changes the timestamp to a human-readable format
    :param timestamp: {int} Unix Timestamp
    :return: {str} Timestamp in human readable form 
    """
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(' ', 'seconds')
    
