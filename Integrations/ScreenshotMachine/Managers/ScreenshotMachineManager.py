# ============================================================================#
# title           :ScreenshotMachineManager.py
# description     :This Module contain all ScreenshotMachine operations functionality
# author          :avital@siemplify.co
# date            :11-04-2018
# python_version  :2.7
# libraries       :requests
# requirements     :
# product_version :1.0
# ============================================================================#

# ============================= IMPORTS ===================================== #

import requests

# ============================== CONSTS ===================================== #

SCREENSHOT_MACHINE_URL = "http://api.screenshotmachine.com/"
NO_CREDITS = "no_credits"
INVALID_CUSTOMER_KEY = "invalid_key"
ERRORS = {
    "no_credits": "Your account is exhausted, you need/should to buy more fresh screenshots.",
    "invalid_hash": "Provided hash is invalid.",
    "invalid_key": "Specified customer API key is invalid.",
    "invalid_url": "Specified URL is invalid or authorization is required (401 Unauthorized status code was sent).",
    "missing_key": "Customer key is missing in your request.",
    "missing_url": "URL parameter is missing in your request.",
    "unsupported": "Free account owners are not allowed to call our API using HTTPS protocol.",
    "system_error": "Generic system error. Oops, sometimes bad things happens in the universe:("
}


# ============================= CLASSES ===================================== #

class ScreenshotMachineManagerError(Exception):
    """
    General Exception for ScreenshotMachine manager
    """
    pass


class ScreenshotMachineLimitManagerError(Exception):
    """
    Limit Exception for ScreenshotMachine manager
    """
    pass


class ScreenshotMachineInvalidAPIKeyManagerError(Exception):
    """
    Invalid Customer API Key Exception for ScreenshotMachine manager
    """
    pass


class ScreenshotMachineManager(object):
    """
    ScreenshotMachine Manager
    """

    def __init__(self, api_key, use_ssl=False):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.verify = use_ssl

    def test_connectivity(self):
        """
        Test connectivity to ScreenshotMachine
        :return: {bool} True if successful, exception otherwise.
        """
        response = self.session.get(SCREENSHOT_MACHINE_URL, params={
            'key': self.api_key,
            'url': 'http://google.com',
            'format': 'jpg',
            'device': 'desktop',
            'dimension': '1024xfull',
            'cacheLimit': 0,
            'delay': 0
        })

        self.validate_response(response, "Unable to connect to ScreenshotMachine.")

        return True

    def get_screenshot(self, url, image_format='jpg', device='desktop',
                       dimension='1024xfull', cacheLimit=0, delay=2000):

        """
        Get a screenshot of a url
        :param url: {str} The url to capture
        :param image_format: {str} Format of the thumbnail or screenshot. Default value is jpg. Available values are: jpg, png, gif
        :param device: {str} You can capture the web page using various devices.There are three options available: desktop, phone, tablet. Default value is desktop.
        :param dimension: {str} Size of the thumbnail or screenshot in format [width]x[height].
            Examples:
                320x240 - screenshot size 320x240 pixels
                800x600 - screenshot size 800x600 pixels
                1024x768 - screenshot size 1024x768 pixels
                1920x1080 - screenshot size 1920x1080 pixels
                1024xfull - full page screenshot with width equals to 1024 pixels (can be pretty long)
        :param cacheLimit: {int} Using cacheLimit parameter, you can manage how old (in days) cached images do you accept. Default value is 14.
        :param delay: {int} Using delay parameter, you can manage how long capturing engine should wait before the screenshot is created. Default value is 200.
            This parameter is useful when you want to capture a webpage with some fancy animation and you want to wait until the animation finish.
        :return: {str} The content of the created screenshot
        """
        response = self.session.get(SCREENSHOT_MACHINE_URL, params={
            'key': self.api_key,
            'url': url,
            'format': image_format,
            'device': device,
            'dimension': dimension,
            'cacheLimit': cacheLimit,
            'delay': delay
        })

        self.validate_response(response, "Unable to get screenshot of {}".format(url))

        # Return screenshot content
        return response.content

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            raise ScreenshotMachineManagerError(
                "{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=error.response.content)
            )

        error = response.headers.get('X-Screenshotmachine-Response')

        if error == NO_CREDITS:
            # No credits left - raise special exception
            raise ScreenshotMachineLimitManagerError(ERRORS[error])

        elif error == INVALID_CUSTOMER_KEY:
            # Invalid customer API key
            raise ScreenshotMachineInvalidAPIKeyManagerError(ERRORS[error])

        elif error:
            # Error message exists - raise it
            raise ScreenshotMachineManagerError(ERRORS[error])
