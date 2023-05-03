from SiemplifyUtils import output_handler
from SiemplifyAction import *
from urlparse import urlparse

HTTP_SCHEME = 'http://'


def validate_url(url):
    """
    Validate URL before sending to
    :param url: {string} URL to Validate.
    :return: {string} Validated URL.
    """
    if urlparse(url)[0]:   # Check if URL contains a scheme in it.
        return url
    return "{0}{1}".format(HTTP_SCHEME, url)


@output_handler
def main():
    siemplify = SiemplifyAction()
    title = siemplify.parameters["Title"]
    url = siemplify.parameters["URL"]

    siemplify.result.add_link(title, validate_url(url))
    siemplify.end("", "true")


if __name__ == '__main__':
    main()
