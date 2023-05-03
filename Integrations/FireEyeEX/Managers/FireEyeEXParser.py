from datamodels import QuarantinedEmail, Alert


class FireEyeEXParser(object):
    """
    FireEye EX Transformation Layer.
    """
    @staticmethod
    def build_siemplify_email_obj(email_data):
        return QuarantinedEmail(raw_data=email_data, sender=email_data.get(u"from"), **email_data)

    @staticmethod
    def build_siemplify_alert_obj(alert_data):
        return Alert(
            raw_data=alert_data,
            smtp_mail_from=alert_data.get(u'src', {}).get(u'smtpMailFrom'),
            smtp_to=alert_data.get(u'dst', {}).get(u'smtpTo'),
            malwares=alert_data.get(u'explanation', {}).get(u'malwareDetected', {}).get(u'malware', []),
            url=alert_data.get(u'alertUrl'),
            action=alert_data.get(u'action'),
            occurred=alert_data.get(u'occurred'),
            smtp_message_subject=alert_data.get(u'smtpMessage', {}).get(u'subject'),
            appliance_id=alert_data.get(u'applianceId'),
            id=alert_data.get(u'id'),
            name=alert_data.get(u'name'),
            retroactive=alert_data.get(u'retroactive'),
            severity=alert_data.get(u'severity'),
            uuid=alert_data.get(u'uuid'),
            ack=alert_data.get(u'ack'),
            product=alert_data.get(u'product'),
            vlan=alert_data.get(u'vlan'),
            malicious=alert_data.get(u'malicious'),
            sc_version=alert_data.get(u'scVersion')
        )