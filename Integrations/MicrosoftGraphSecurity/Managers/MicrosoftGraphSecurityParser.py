from datamodels import Alert


class MicrosoftGraphSecurityParser(object):
    """
   Microsoft Graph Security Transformation Layer.
    """

    @staticmethod
    def build_siemplify_alert_obj(alert_data):
        return Alert(raw_data=alert_data,
                     vendor=alert_data.get('vendorInformation', {}).get('vendor'),
                     provider=alert_data.get('vendorInformation', {}).get('provider'),
                     **alert_data)
