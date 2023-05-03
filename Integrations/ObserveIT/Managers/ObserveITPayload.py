class ObserveITPayload(object):
    @staticmethod
    def get_authorization_payload(client_id, client_secret):
        # type: (str or unicode, str or unicode) -> dict
        """
        Get payload dict to make request with
        @param client_id: Client ID to authorize with
        @param client_secret: Client Secret to authorize with
        @return: Payload for request
        """
        return {
            u'data': {
                u'grant_type': 'client_credentials',
                u'client_id': client_id,
                u'client_secret': client_secret,
                u'scope': '*'
            },
            u'headers': {
                u'Content-Type': u'application/x-www-form-urlencoded'
            }
        }

    @staticmethod
    def get_test_connectivity_payload():
        # type: () -> dict
        """
        Get payload dict to make request with
        @return: Payload for request
        """
        return {}

    @staticmethod
    def get_alerts_payload(severities, timestamp, limit):
        # type: (str or unicode, int, int) -> dict
        """
        Get payload dict to make request with
        @param severities: Severities to start from
        @param timestamp: Timestamp to start from
        @param limit: How many alerts to take
        @return: Payload for request
        """
        severities_filter = u','.join([u'eq(severity,{})'.format(severity) for severity in severities])

        return {
            u'params': {
                # TODO: Write a constructor for RQL.
                u'rql': u'and(select(),or({}),ge(risingValue,epoch:{}),limit({},0))'
                        .format(severities_filter, timestamp, limit),
            }
        }
