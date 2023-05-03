import requests
import re
import json
import ipaddress
from constants import (
    IPV4_TYPE_STRING,
    IPV6_TYPE_STRING
)


def validate_response(response, error_msg=u'An error occurred'):
    """
    Validate response
    :param response: {requests.Response} The response to validate
    :param error_msg: {unicode} Default message to display on error
    """
    try:
        response.raise_for_status()

    except requests.HTTPError as error:
        raise Exception(
            u'{error_msg}: {error} {text}'.format(
                error_msg=error_msg,
                error=error,
                text=error.response.content)
        )

    return True


def valid_ip_address(ip_address):
    """
    :type ip_address: {unicode}
    :return: {unicode}
    """
    ip_exploded = ipaddress.ip_address(ip_address).exploded

    def is_ipv4(s):
        try:
            return str(int(s)) == s and 0 <= int(s) <= 255
        except:
            return False

    def is_ipv6(s):
        if len(s) > 4:
            return False
        try:
            return int(s, 16) >= 0 and s[0] != u'-'
        except:
            return False

    if ip_exploded.count(u'.') == 3 and all(is_ipv4(i) for i in ip_exploded.split(u'.')):
        return IPV4_TYPE_STRING
    if ip_exploded.count(u':') == 7 and all(is_ipv6(i) for i in ip_exploded.split(u':')):
        return IPV6_TYPE_STRING
    return None


def permissive_json_loads(json_string):
    _rePattern = re.compile(r'''(\d+)\)$''', re.MULTILINE)

    i = 0
    #  Make sure the loop is going to terminate.
    #  There wont be more iterations than the double amount of characters
    while True:
        i += 1
        if i > len(json_string) * 2:
            return
        try:
            data = json.loads(json_string)
        except ValueError, exc:
            ex_msg = str(exc)
            if ex_msg.startswith(u'Invalid \\escape'):
                m = re.search(_rePattern, ex_msg)
                if not m:
                    return

                pos = int(m.groups()[0])
                print u"Replacing at: %d" % pos
                json_string = json_string[:pos] + '\\' + json_string[pos:]
            else:
                raise
        else:
            return data

