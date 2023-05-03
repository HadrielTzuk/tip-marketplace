from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import convert_string_to_unix_time
from TIPCommon import dict_to_flat


class QuarantinedEmail(object):
    def __init__(self, raw_data, email_uuid=None, queue_id=None, message_id=None, completed_at=None,
                 timestamp=None, sender=None, subject=None, appliance_id=None, **kwargs):
        self.raw_data = raw_data
        self.email_uuid = email_uuid
        self.queue_id = queue_id
        self.message_id = message_id
        self.completed_at = completed_at
        self.timestamp = timestamp
        self.sender = sender
        self.subject = subject
        self.appliance_id = appliance_id

    def as_csv(self):
        return {
            u"Sender": self.sender,
            u"Subject": self.subject,
            u"Completed At": self.completed_at or self.timestamp,
            u"Email UUID": self.email_uuid,
            u"Message ID": self.message_id,
            u"Queue ID": self.queue_id
        }


class Alert(object):
    def __init__(
            self,
            raw_data,
            smtp_mail_from=None,
            smtp_to=None,
            malwares=None,
            url=None,
            action=None,
            occurred=None,
            smtp_message_subject=None,
            appliance_id=None,
            id=None,
            name=None,
            retroactive=None,
            severity=None,
            uuid=None,
            ack=None,
            product=None,
            vlan=None,
            malicious=None,
            sc_version=None
    ):
        self.raw_data = raw_data
        self.smtp_mail_from = smtp_mail_from
        self.smtp_to = smtp_to
        self.malwares = malwares if malwares else []
        self.url = url
        self.action = action
        self.occurred = occurred
        self.smtp_message_subject = smtp_message_subject
        self.appliance_id = appliance_id
        self.id = id
        self.name = name
        self.retroactive = retroactive
        self.severity = severity
        self.uuid = uuid
        self.ack = ack
        self.product = product
        self.vlan = vlan
        self.malicious = malicious
        self.sc_version = sc_version

    @property
    def priority(self):
        if self.severity == u"MAJR":
            return 80
        elif self.severity == u"CRIT":
            return 100

        return 60

    @property
    def email_id(self):
        return u"-".join([self.smtp_message_subject, self.smtp_to, self.smtp_mail_from])

    @property
    def event(self):
        event = {
            u'smtpTo': self.smtp_to,
            u'smtpMailFrom': self.smtp_mail_from,
            u'subject': self.smtp_message_subject,
            u'startTime': self.occurred_time_unix,
            u'endTime': self.occurred_time_unix,
            u'action': self.action,
            u'alert_uuid': self.uuid
        }

        for malware in self.malwares:
            if u'type' not in malware:
                event.update(malware)
            else:
                malware_type = malware[u'type']
                if not malware_type in event:
                    event[malware_type] = []

                event[malware_type].append(malware)

        return event

    @property
    def occurred_time_unix(self):
        return convert_string_to_unix_time(self.occurred)

