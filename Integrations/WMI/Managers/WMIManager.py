# ============================================================================#
# title           :WMIManager.py
# description     :This Module contain all WMI operations functionality
# author          :avital@siemplify.co
# date            :20-02-2018
# python_version  :2.7
# libreries       :wmi
# requirments     : A user with WMI access to the given server.
#                   Enabling WMI access tutorial:
#                   http://www.gsx.com/blog/bid/86455/enable-remote-wmi-access-for-a-domain-user-account
# product_version :1.0
# ============================================================================#

# ============================= IMPORTS ===================================== #




# ============================= CLASSES ===================================== #


class WMIManagerError(Exception):
    """
    General Exception for WMI manager
    """
    pass


class WMIManagerBuilder(object):
    @staticmethod
    def create_manager(server_addr, username=None, password=None, is_linux=False):
        if is_linux:
            return WMIManagerPosix(server_addr, username, password)

        return WMIManager(server_addr, username, password)


class WMIManager(object):

    def __init__(self, server_addr, username=None, password=None):
        """
        Connect to a WMI instance
        """
        try:
            import wmi
            # Connect to WMI instance with given credentials
            self.wmi = wmi.WMI(server_addr, user=username, password=password)

        except Exception as error:
            raise WMIManagerError(
                "Unable to connect to {server}: {error} {text}".format(
                    server=server_addr,
                    error=error,
                    text=error.message)
            )

    def run_query(self, wql_query):
        """
        Run a WQL query
        :return: {list} List of the items returned by the query (each item is a dict)
        """
        try:
            wmi_items = self.wmi.query(wql_query)
            items = []

            # Extract useful data from wmi items and add it to items list
            for item in wmi_items:
                items.append(
                    {p: unicode(getattr(item, p)).encode('utf-8') for p in
                     item.properties})

            return items

        except Exception as e:
            raise WMIManagerError(e.message)

    def get_services(self):
        """
        Get a list of services that are configured on the system
        :return: {list} List of the services' information (each service is a dict)
        """
        try:

            wmi_services = self.wmi.Win32_Service()
            services = []

            # Extract useful data from wmi services and add it to services list
            for service in wmi_services:
                services.append(
                    {p: unicode(getattr(service, p)).encode('utf-8') for p in
                     service.properties})

            return services

        except Exception as e:
            raise WMIManagerError(e.message)

    def get_users(self):
        """
        Get a list of users that are configured on the system
        :return: {list} List of the users' information (each user is a dict)
        """
        try:
            wmi_users = self.wmi.Win32_UserAccount()
            users = []

            # Extract useful data from wmi users and add it to users list
            for user in wmi_users:
                users.append(
                    {p: unicode(getattr(user, p)).encode('utf-8') for p in
                     user.properties})

            return users

        except Exception as e:
            raise WMIManagerError(e.message)

    def get_system_info(self):
        """
        Get a information about the system
        :return: {dict} System information
        """
        try:
            # Only 1 item is supposed to return
            wmi_system_info = self.wmi.Win32_ComputerSystem()[0]
            info = {p: unicode(getattr(wmi_system_info, p)).encode('utf-8') for
                    p in wmi_system_info.properties}

            # Only 1 item is supposed to return
            wmi_os_info = self.wmi.Win32_OperatingSystem()[0]
            # Add OS info to collected info
            info.update(
                {p: unicode(getattr(wmi_os_info, p)).encode('utf-8') for p in
                 wmi_os_info.properties})

            return info

        except Exception as e:
            raise WMIManagerError(e.message)

    def construct_csv(self, results):
        csv_output = []
        headers = reduce(set.union, map(set, map(dict.keys, results)))

        csv_output.append(",".join(map(str, headers)))

        for result in results:
            csv_output.append(
                ",".join([s.replace(',', ' ') for s in
                          map(str, [result.get(h, None) for h in headers])]))

        return csv_output


class WMIManagerPosix(object):

    def __init__(self, server_addr, username=None, password=None):
        """
        Connect to a WMI instance
        """
        try:
            import wmi_client_wrapper as wmi

            # Connect to WMI instance with given credentials
            self.wmi = wmi.WmiClientWrapper(host=server_addr, username=username, password=password)

            # Test the connection
            self.wmi.query("SELECT * FROM Win32_Processor")
        except:
            raise WMIManagerError(
                "Unable to connect to {server}".format(
                    server=server_addr)
            )

    def run_query(self, wql_query):
        """
        Run a WQL query
        :return: {list} List of the items returned by the query (each item is a dict)
        """
        try:
            return self.wmi.query(wql_query)

        except Exception as e:
            raise WMIManagerError(e.message)

    def get_services(self):
        """
        Get a list of services that are configured on the system
        :return: {list} List of the services' information (each service is a dict)
        """
        try:

            return self.wmi.query("SELECT * FROM Win32_Service")

        except Exception as e:
            raise WMIManagerError(e.message)

    def get_users(self):
        """
        Get a list of users that are configured on the system
        :return: {list} List of the users' information (each user is a dict)
        """
        try:
            return self.wmi.query("SELECT * FROM Win32_UserAccount")

        except Exception as e:
            raise WMIManagerError(e.message)

    def get_system_info(self):
        """
        Get a information about the system
        :return: {dict} System information
        """
        try:
            # Only 1 item is supposed to return
            info = self.wmi.query("SELECT * FROM Win32_ComputerSystem")[0]

            # Only 1 item is supposed to return
            # Add OS info to collected info
            info.update(self.wmi.query("SELECT * FROM Win32_OperatingSystem")[0])

            return info

        except Exception as e:
            raise WMIManagerError(e.message)

    def construct_csv(self, results):
        csv_output = []
        headers = reduce(set.union, map(set, map(dict.keys, results)))

        csv_output.append(",".join(map(str, headers)))

        for result in results:
            csv_output.append(
                ",".join([s.replace(',', ' ') for s in
                          map(str, [result.get(h, None) for h in headers])]))

        return csv_output



