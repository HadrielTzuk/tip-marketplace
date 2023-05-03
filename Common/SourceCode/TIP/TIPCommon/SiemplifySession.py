"""
SiemplifySession
==================

SiemplifySession is a class for managing Siemplify sessions.

This class inherits from `Session` and provides a way to encode sensitive data in error messages.

The following attributes are available:

* `sensitive_data_arr`: A list of sensitive data strings.

The following methods are available:

* `request()`: Makes a request to the Siemplify API.
* `encode_sensitive_data()`: Encodes sensitive data in an error message.
* `encode_data()`: Encodes a string.


Examples
--------

* Create a SiemplifySession object.

    
    
    ```session = SiemplifySession(["password", "user_name"])
    ```

* Encode sensitive data in an error message.

    
    
    ```message = "An error occurred while connecting to the Siemplify API: {}.".format(session.encode_sensitive_data("password"))
    ```

* Encode a string.

    
    
    ```encoded_string = session.encode_data("password")
    ```
"""

from requests import Session


class SiemplifySession(Session):
    """A class for managing Siemplify sessions.

    This class inherits from `Session` and provides a way to encode sensitive data in error messages.

    The following attributes are available:

    * `sensitive_data_arr`: A list of sensitive data strings.

    The following methods are available:

    * `request()`: Makes a request to the Siemplify API.
    * `encode_sensitive_data()`: Encodes sensitive data in an error message.
    * `encode_data()`: Encodes a string.
    """

    def __init__(self, sensitive_data_arr=[]):
        """Creates a SiemplifySession object.

        Args:
            sensitive_data_arr (list): A list of sensitive data strings.
        """
        Session.__init__(self)
        self.sensitive_data_arr = sensitive_data_arr

    def request(self, method, url, **kwargs):
        """Makes a request to the Siemplify API.

            Args:
                method (str): The HTTP method to use.
                url (str): The URL to request.
                **kwargs: Additional keyword arguments to pass to the request.

            Returns:
                The response from the request.
            """
        try:
            return super(SiemplifySession, self).request(method, url, **kwargs)
        except Exception as e:
            err_msg = str(e)
            try:
                e.args = map(
                    lambda err: self.encode_sensitive_data(err),
                    e.args
                )
                e.message = self.encode_sensitive_data(err_msg)
            except Exception:
                raise Exception(self.encode_sensitive_data(err_msg))
            raise

    def encode_sensitive_data(self, message):
        """Encodes sensitive data in an error message.

        Args:
            message (str): The error message which may contain sensitive data.

        Returns:
            The error message with encoded sensitive data.
        """
        for sensitive_data in self.sensitive_data_arr:
            message = message.replace(
                sensitive_data,
                self.encode_data(sensitive_data)
            )
        return message

    @staticmethod
    def encode_data(sensitive_data):
        """Encodes a string.

        Args:
            sensitive_data (str): The string to encode.

        Returns:
            The encoded string.
        """
        if len(sensitive_data) > 1:
            return u"{}...{}".format(sensitive_data[0], sensitive_data[-1])
        return sensitive_data
