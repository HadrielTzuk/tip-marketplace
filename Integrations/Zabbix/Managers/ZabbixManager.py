# ============================================================================#
# title           :JiraManager.py
# description     :This Module contain all Zabbix operations functionality
# author          :avital@siemplify.co
# date            :21-01-2018
# python_version  :2.7
# libreries       :pyzabbix
# requirments     :
# Product Version: 2.2 (Assumed by VM OS type)
# ============================================================================#

# ============================= IMPORTS ===================================== #

from pyzabbix import ZabbixAPI, ZabbixAPIException
import json

# ============================== CONSTS ===================================== #

EXTEND_QUERY = 'extend'
EXECUTION_FAILED = "failed"
EXECUTION_SUCCEEDED = "success"

# ============================= CLASSES ===================================== #


class ZabbixManagerError(Exception):
    """
    General Exception for Zabbix manager
    """
    pass


class ZabbixManager(object):

    def __init__(self, server_addr, username, password, verify_ssl=False):
        """
        Connect to a Zabbix instnace
        """
        try:
            # Connect to Zabbix instance with given credentials
            self.zabbix = ZabbixAPI(server_addr)
            self.zabbix.session.verify = verify_ssl
            self.zabbix.login(username, password)

        except Exception as error:
            raise ZabbixManagerError(
                u"Unable to connect to {server}: {error} {text}".format(
                    server=server_addr,
                    error=error,
                    text=error.message)
            )

    def get_events(self, acknowledged=None, eventids=None, hostsids=None,
                   groupids=None):
        """
        Get events from Zabbix instance
        :param acknowledged: {bool} If set to true return only acknowledged events.
        :param eventids: {string/array} Return only events with the given IDs.
        :param hostsids: {string/array} Return only events created by objects that belong to the given hosts.
        :param groupids: {string/array} Return only events created by objects that belong to the given host groups.
        :return: {list} The events
        """
        try:
            return self.zabbix.event.get(
                output=EXTEND_QUERY,
                expandDescription=1,
                selectHosts=EXTEND_QUERY,
                selectRelatedObject=EXTEND_QUERY,
                select_acknowledges=EXTEND_QUERY,
                acknowledged=acknowledged,
                eventids=eventids,
                hostids=hostsids,
                groupids=groupids
            )

        except Exception as error:
            raise ZabbixManagerError(
                u"Unable to get events: {error} {text}".format(
                    error=error,
                    text=error.message)
            )

    def get_triggers(self, monitored=False, active=False, triggerids=None,
                     hostids=None, select_last_event=False, problematic=False, last_change_since=None):
        """
        Get triggers from Zabbix instance
        :param monitored: {bool} Return only enabled triggers that belong to monitored hosts and contain only enabled items.
        :param active: {bool} Return only enabled triggers that belong to monitored hosts.
        :param triggerids: {string/array} Return only triggers with the given IDs.
        :param hostsids: {string/array} Return only events created by objects that belong to the given hosts.
        :param select_last_event: {bool} If set to true return the last trigger event in the lastEvent property.
        :param problematic: {bool}: If set to true return only triggers in problem state.
        :param last_change_since: {str} Return only triggers that have changed their state after the given time (unix timestamp)
        :return: {list} The events
        """
        filters = {'value': '1'} if problematic else {}
        return self.zabbix.trigger.get(
            output=EXTEND_QUERY,
            expandDescription=True,
            monitored=monitored,
            active=active,
            triggerids=triggerids,
            hostids=hostids,
            expandExpression=True,
            expandComment=True,
            selectLastEvent=select_last_event,
            selectTags=EXTEND_QUERY,
            lastChangeSince=last_change_since,
            filter=filters
        )

    def get_hosts(self, monitored=False, triggerids=None, hostids=None, filter=None):
        """
        Get hosts from Zabbix instance
        :param monitored: {bool} Return only enabled triggers that belong to monitored hosts and contain only enabled items.
        :param triggerids: {string/array} Return only hosts that have the given triggers.
        :param hostsids: {string/array} Return only hosts with the given host IDs.
        :return: {list} The events
        """
        return self.zabbix.host.get(
            output=EXTEND_QUERY,
            expandDescription=True,
            monitored_hosts=monitored,
            triggerids=triggerids,
            hostids=hostids,
            selectInterfaces=EXTEND_QUERY,
            filter=filter
        )

    def get_discovered_services(self, dserviceids=None, dhostids=None,
                                dcheckids=None):
        """
        Get discovery services from Zabbix instance
        :param dserviceids {string/list} Return only discovered services with the given IDs.
        :param dhostids {string/list} Return only discovered services that belong to the given discovered hosts.
        :param dcheckids {string/list} Return only discovered services that have been detected by the given discovery checks.
        :return: {list} The events
        """
        return self.zabbix.dservice.get(
            dserviceids=dserviceids,
            dhostids=dhostids,
            dcheckids=dcheckids,
            selectDRules=EXTEND_QUERY,
            selectDHosts=EXTEND_QUERY,
            selectHosts=EXTEND_QUERY,
            output=EXTEND_QUERY,
            expandDescription=1
        )

    def get_ldd_rules(self, itemids=None, hostids=None, monitored=True):
        """
        Get LDD rules from Zabbix instance
        :param itemids {string/list} Return only LLD rules with the given IDs.
        :param hostids {string/list} Return only LLD rules that belong to the given hosts.
        :param monitored {string/list} If set to true return only enabled LLD rules that belong to monitored hosts.
        :return: {list} The events
        """
        return self.zabbix.discoveryrule.get(
            itemids=itemids,
            hostids=hostids,
            monitored=monitored,
            selectItems=EXTEND_QUERY,
            selectTriggers=EXTEND_QUERY
        )

    def get_hosts_by_ip(self, ip):
        return self.get_hosts(filter={"ip": ip})

    def execute_script(self, host_id, script_id):
        return self.zabbix.script.execute(
            hostid=host_id,
            scriptid=script_id
        )

    def get_scripts(self, filter=None):
        return self.zabbix.script.get(filter=filter)

    def get_script_by_name(self, name):
        scripts = self.get_scripts(filter={"name": name})

        if not scripts:
            raise ZabbixManagerError(u"Script {} was not found".format(name))

        return scripts[0]