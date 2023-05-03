# ==============================================================================
# title           : MSSQL.py
# description     : MS SQL lib to get data from MS SQL.
# author          : nikolay.ryagin@gmail.com
# date            : 12-14-17
# python_version  : 2.7
# libraries       : -
# requirements    : MS SQL Driver and pyodbc
# product_version : 1.0
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================

import pyodbc
from subprocess import Popen, PIPE
from functools import partial

# =====================================
#              CONSTS                 #
# =====================================

KINIT_COMMAND = u'/usr/bin/kinit'
DEFAULT_DRIVERS_FALLBACK_ORDERED = (
    u'ODBC Driver 18 for SQL Server',
    u'ODBC Driver 17 for SQL Server',
    u'ODBC Driver 13 for SQL Server'
)
DEFAULT_DRIVER = u'{ODBC Driver 13 for SQL Server}'

# =====================================
#              CLASSES                #
# =====================================


class MSSQLException(Exception):
    pass


class MSSQLManager(object):
    """
    The class defines some methods which help to get data from MS SQL databases.
    """

    def __init__(self, username, password, server, database, use_kerberos=False, kerberos_realm=None,
                 kerberos_username=None, kerberos_password=None, siemplify=None, verify_ssl=True, **kwargs):
        """
        The method initialises required parameters for connection to MS SQL.
        :param username: SQL login name;
        :param password: password for SQL name;
        :param server: IP or DNS name of SQL Server;
        :param database: Database name;
        :param kwargs: Use for additional parameters like port if you're using non default instance,
        driver if you're using another version of MS SQL;
        """

        self.username = username
        self.password = password
        self.use_kerberos = use_kerberos
        self.kerberos_realm = kerberos_realm
        self.kerberos_username = kerberos_username
        self.kerberos_password = kerberos_password
        self.server = server
        self.database = database
        self.siemplify = siemplify
        self.verify_ssl = 'no' if verify_ssl else 'yes'

        if u'port' in kwargs.keys():
            self.server = u','.join((self.server, unicode(kwargs['port'])))

        if u'driver' in kwargs.keys():
            self.driver = kwargs[u'driver']
        else:
            self.driver = None

        if u'trusted' in kwargs.keys() and kwargs[u'trusted']:
            self.trusted = u'yes'
            self.win_auth = True

        else:
            self.trusted = u'no'
            self.win_auth = False

    def connect(self):
        """
        The method returns pyodbc connection object with established connection to database.
        :return: pyodbc object.
        """
        if self.win_auth:
            if self.use_kerberos:
                # Run kinit to obtain kerberos token before trying to connect (linux only!)
                kinit_args = [KINIT_COMMAND, u'{}@{}'.format(self.kerberos_username, self.kerberos_realm)]
                kinit = Popen(kinit_args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
                kinit.stdin.write(u'{}\n'.format(self.kerberos_password))
                out, err = kinit.communicate()
                ret_code = kinit.returncode

                if ret_code != 0:
                    raise MSSQLException(
                        u"Kinit command failed (ret code: {}). Output: {}. Error: {}".format(ret_code, out, err)
                    )

            connection_string_template = ur'Driver={driver};' \
                                         u'Server={server};' \
                                         u'Database={database};' \
                                         u'Trusted_Connection={trusted_connection};' \
                                         u'TrustServerCertificate={verify_ssl};'

            connection_string = partial(connection_string_template.format,
                                       server=self.server,
                                       database=self.database,
                                       trusted_connection=self.trusted,
                                       verify_ssl=self.verify_ssl)
        else:
            connection_string_template = ur'Driver={driver};' \
                                         u'Server={server};' \
                                         u'Database={database};' \
                                         u'Trusted_Connection={trusted_connection};' \
                                         u'uid={uid};' \
                                         u'pwd={pwd};' \
                                         u'TrustServerCertificate={verify_ssl};'
            connection_string = partial(connection_string_template.format,
                                       server=self.server,
                                       database=self.database,
                                       trusted_connection=self.trusted,
                                       uid=self.username,
                                       pwd=self.password,
                                       verify_ssl=self.verify_ssl)
        drivers = [self.driver] if self.driver is not None else DEFAULT_DRIVERS_FALLBACK_ORDERED
        installed_drivers = pyodbc.drivers()
        if self.siemplify is not None:
            self.siemplify.LOGGER.info("Checking installed drivers: {}".format(', '.join(installed_drivers)))
        for driver in drivers:
            if driver in installed_drivers:
                if self.siemplify is not None:
                    self.siemplify.LOGGER.info("Most recent among supported selected: {}".format(driver))
                return pyodbc.connect(connection_string(driver=driver))
        raise MSSQLException(
            "01000. No supported driver has found installed, from drivers list: {}".format(', '.join(drivers))
        )

    def _getData(self, rows, keys):
        """
        The method converts list of raw to JSON like format.
        :param rows: data in rows from MS SQL database;
        :param keys: column name from MS SQL query;
        :return: data from query.
        """

        data = []
        for row in rows:
            temp = {k: v for k, v in zip(keys, list(row))}
            data.append(temp)

        return data

    def testConnection(self):
        """
        The method is defined to test connection to MS SQL.
        :return: 
        """
        self.connect()
        return True

    def executeQuery(self, query):
        """
        The method makes query on MS SQL database and provide results.
        :param query: SQL query like 'SELECT * FROM exampleDB'
        :return: JSON like results
        """
        try:
            cursor = self.connect().cursor()

            data = []

            cursor.execute(query)

            if cursor.description:
                columns = [column[0] for column in cursor.description]
                rows = cursor.fetchall()
                data = self._getData(rows, columns)

            self.connect().close()

            return data

        except pyodbc.Error as err:
            raise MSSQLException(err)

    @staticmethod
    def construct_csv(results):
        """
        The method costructs a csv from query results.
        :param results: The list_of_dicts to add to the csv (list_of_dicts are list of flat dicts)
        :return: {list} csv formatted list
        """
        csv_output = []
        headers = reduce(set.union, map(set, map(dict.keys, results)))

        csv_output.append(",".join([h.encode("utf-8") if isinstance(h, unicode) else h for h in headers]))

        for result in results:
            csv_output.append(
                ",".join([s.replace(',', ' ') for s in
                          map(str, [result.get(h, "").encode("utf-8") if isinstance(result.get(h, ""),
                                                                                    unicode) else result.get(h, "")
                                    for
                                    h in headers])]))

        return csv_output


# 