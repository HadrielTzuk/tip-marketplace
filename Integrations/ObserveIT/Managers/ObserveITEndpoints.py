import urlparse

from ObserveITConstants import (
    GET,
    POST
)


class ObserveITEndpoints(object):
    @staticmethod
    def get_authorization_endpoint(api_root):
        # type: (str or unicode) -> (str or unicode, str or unicode)
        """
        Get method and endpoint to call with
        @param api_root: API Root
        @return: Method and Endpoint
        """
        return POST, urlparse.urljoin(api_root, u'/v2/apis/auth/oauth/token')

    @staticmethod
    def get_test_connectivity_endpoint(api_root):
        # type: (str or unicode) -> (str or unicode, str or unicode)
        """
        Get method and endpoint to call with
        @param api_root: API Root
        @return: Method and Endpoint
        """
        return GET, urlparse.urljoin(api_root, u'/v2/apis/report;realm=observeit/_health')

    @staticmethod
    def get_alerts_endpoint(api_root):
        # type: (str or unicode) -> (str or unicode, str or unicode)
        """
        Get method and endpoint to call with
        @param api_root: API Root
        @return: Method and Endpoint
        """
        return GET, urlparse.urljoin(api_root, u'/v2/apis/report;realm=observeit/reports/alert_v0/data')
