INTEGRATION_NAME = u'ArcSightLogger'
PING_SCRIPT_NAME = u'{} - Ping'.format(INTEGRATION_NAME)
SEND_QUERY_SCRIPT_NAME = u'{} - Send Query'.format(INTEGRATION_NAME)

PAGE_LIMIT = 100

ENDPOINTS = {
    u'login': u'/core-service/rest/LoginService/login',
    u'logout': u'/core-service/rest/LoginService/logout',
    u'search': u'/server/search',
    u'status': u'/server/search/status',
    u'events': u'/server/search/events',
}

LOGIN_HEADERS = {u'Accept': u'application/json', u'Content-Type': u'application/x-www-form-urlencoded'}
REQUEST_HEADERS = {u'Accept': u'application/json', u'Content-Type': u'application/json'}

LOGIN_DATA = u'login={}&password={}'
LOGOUT_DATA = u'authToken={}'

QUERY_STATUS_COMPLETED = u'complete'
QUERY_STATUS_RUNNING = u'running'
QUERY_STATUS_STARTING = u'starting'
QUERY_STATUS_ERROR = u'error'

DEFAULT_TIME_FRAME = u'1h'
TIME_UNIT_MAPPER = {u'w': u'weeks', u'd': u'days', u'h': u'hours', u'm': u'minutes', u's': u'seconds'}