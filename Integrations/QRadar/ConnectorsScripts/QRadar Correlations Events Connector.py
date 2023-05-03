from SiemplifyUtils import output_handler
# ==============================================================================
# title           :QRadar Correlations Events Connector.py
# description     :This Module contain QRadar Connector logic.
# author          :victor@siemplify.co
# date            :01-04-18
# python_version  :2.7
# libraries       : -
# requirements    :
# product_version : v7.2.8 , v7.3.1
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
from QRadarManager import QRadarManager
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import CaseInfo
from SiemplifyUtils import convert_unixtime_to_datetime, dict_to_flat, convert_datetime_to_unix_time, utc_now
import uuid
import sys
import datetime
import os
import json
import collections
import arrow

# =====================================
#             CONSTANTS               #
# =====================================
CATEGORY_HUMAN_READABLE = {
    "18150": "AAA Authentication Failed",
    "18151": "AAA Authentication Succeeded",
    "18148": "AAA Session Denied",
    "18147": "AAA Session Ended",
    "18146": "AAA Session Started",
    "18149": "AAA Session Status",
    "4013": "ACL Deny",
    "4012": "ACL Permit",
    "7069": "ARP Poisoning",
    "4015": "Access Denied",
    "4014": "Access Permitted",
    "8065": "Access point radio failure",
    "5027": "ActiveX Exploit",
    "3113": "Admin Login Attempt",
    "3015": "Admin Login Failure",
    "3014": "Admin Login Successful",
    "3060": "Admin Logout",
    "16006": "Admin Session Created",
    "16007": "Admin Session Destroyed",
    "3074": "Admin Session Finished",
    "3073": "Admin Session Started",
    "21004": "Administration",
    "6015": "Adware Detected",
    "8060": "Alert",
    "11003": "Anomaly",
    "8029": "Application Installed",
    "9007": "Application Policy Violation",
    "1002": "Application Query ",
    "8034": "Application Uninstalled",
    "23081": "Asset Client Application Cleaned",
    "23084": "Asset Client Application Deleted",
    "23083": "Asset Client Application Moved",
    "23082": "Asset Client Application Observed",
    "23001": "Asset Created",
    "23005": "Asset Deleted",
    "23093": "Asset Deviation Report",
    "23006": "Asset Hostname Cleaned",
    "23007": "Asset Hostname Created",
    "23011": "Asset Hostname Deleted",
    "23010": "Asset Hostname Moved",
    "23009": "Asset Hostname Observed",
    "23008": "Asset Hostname Updated",
    "23036": "Asset IP Address Cleaned",
    "23037": "Asset IP Address Created",
    "23041": "Asset IP Address Deleted",
    "23040": "Asset IP Address Moved",
    "23039": "Asset IP Address Observed",
    "23038": "Asset IP Address Updated",
    "23042": "Asset Interface Cleaned",
    "23043": "Asset Interface Created",
    "23048": "Asset Interface Deleted",
    "23047": "Asset Interface Merged",
    "23046": "Asset Interface Moved",
    "23045": "Asset Interface Observed",
    "23044": "Asset Interface Updated",
    "23004": "Asset Moved",
    "23024": "Asset OS Cleaned",
    "23025": "Asset OS Created",
    "23029": "Asset OS Deleted",
    "23028": "Asset OS Moved",
    "23027": "Asset OS Observed",
    "23026": "Asset OS Updated",
    "23003": "Asset Observed",
    "23073": "Asset Patch Scan Cleaned",
    "23074": "Asset Patch Scan Created",
    "23076": "Asset Patch Scan Deleted",
    "23075": "Asset Patch Scan Moved",
    "23085": "Asset Patch Scan Observed",
    "23012": "Asset Port Cleaned",
    "23013": "Asset Port Created",
    "23017": "Asset Port Deleted",
    "23016": "Asset Port Moved",
    "23015": "Asset Port Observed",
    "23077": "Asset Port Scan Cleaned",
    "23078": "Asset Port Scan Created",
    "23080": "Asset Port Scan Deleted",
    "23079": "Asset Port Scan Moved",
    "23086": "Asset Port Scan Observed",
    "23014": "Asset Port Updated",
    "23030": "Asset Property Cleaned",
    "23031": "Asset Property Created",
    "23035": "Asset Property Deleted",
    "23034": "Asset Property Moved",
    "23033": "Asset Property Observed",
    "23032": "Asset Property Updated",
    "23053": "Asset Scanned Policy Cleaned",
    "23056": "Asset Scanned Policy Deleted",
    "23055": "Asset Scanned Policy Moved",
    "23054": "Asset Scanned Policy Observed",
    "23061": "Asset Scanned Service Cleaned",
    "23064": "Asset Scanned Service Deleted",
    "23063": "Asset Scanned Service Moved",
    "23062": "Asset Scanned Service Observed",
    "23069": "Asset UNIX Patch Cleaned",
    "23072": "Asset UNIX Patch Deleted",
    "23071": "Asset UNIX Patch Moved",
    "23070": "Asset UNIX Patch Observed",
    "23002": "Asset Updated",
    "23049": "Asset User Cleaned",
    "23052": "Asset User Deleted",
    "23051": "Asset User Moved",
    "23050": "Asset User Observed",
    "23018": "Asset Vuln Instance Cleaned",
    "23019": "Asset Vuln Instance Created",
    "23023": "Asset Vuln Instance Deleted",
    "23022": "Asset Vuln Instance Moved",
    "23021": "Asset Vuln Instance Observed",
    "23020": "Asset Vuln Instance Updated",
    "23057": "Asset Windows Application Cleaned",
    "23060": "Asset Windows Application Deleted",
    "23059": "Asset Windows Application Moved",
    "23058": "Asset Windows Application Observed",
    "23065": "Asset Windows Patch Cleaned",
    "23068": "Asset Windows Patch Deleted",
    "23067": "Asset Windows Patch Moved",
    "23066": "Asset Windows Patch Observed",
    "18108": "Auth Closed",
    "18113": "Auth Delayed",
    "18111": "Auth Denied",
    "18112": "Auth In Progress",
    "18107": "Auth Opened",
    "18114": "Auth Queued",
    "18115": "Auth Redirected",
    "18109": "Auth Reset",
    "3010": "Auth Server Login Failed",
    "3011": "Auth Server Login Succeeded",
    "3058": "Auth Server Logout",
    "3054": "Auth Server Session Closed",
    "3053": "Auth Server Session Opened",
    "18110": "Auth Terminated",
    "18423": "Authentication (Application)",
    "8051": "Authentication",
    "6002": "Backdoor Detected",
    "19023": "Backup Activity Attempted",
    "19025": "Backup Activity Failed",
    "19024": "Backup Activity Succeeded",
    "7063": "Bad Content",
    "11001": "Behavioral",
    "22017": "Billing Event",
    "7058": "Blacklist Address",
    "7061": "Botnet Address",
    "5024": "Browser Exploit",
    "2016": "Brute force login",
    "5002": "Buffer Overflow",
    "19002": "Built	",
    "19003": "Bulk Copy",
    "17005": "Bulk Host Discovered",
    "18392": "CUPS Session Closed",
    "18395": "CUPS Session Denied",
    "18396": "CUPS Session In Progress",
    "18391": "CUPS Session Opened",
    "18393": "CUPS Session Reset",
    "18394": "CUPS Session Terminated",
    "18386": "CVS Session Closed",
    "18389": "CVS Session Denied",
    "18390": "CVS Session In Progress",
    "18385": "CVS Session Opened",
    "18387": "CVS Session Reset",
    "18388": "CVS Session Terminated",
    "19026": "Capture Activity Attempted",
    "19028": "Capture Activity Failed",
    "19027": "Capture Activity Succeeded",
    "3111": "Certificate Mismatch",
    "18398": "Chargen Session Closed",
    "18401": "Chargen Session Denied",
    "18402": "Chargen Session In Progress",
    "18399": "Chargen Session Reset",
    "18397": "Chargen Session Started",
    "18400": "Chargen Session Terminated",
    "18424": "Chat",
    "18085": "Chat Closed",
    "18088": "Chat Denied",
    "18089": "Chat In Progress",
    "18084": "Chat Opened",
    "18090": "Chat Redirected",
    "18086": "Chat Reset",
    "18087": "Chat Terminated",
    "18425": "Client Server",
    "8067": "Client device or authentication server misconfigured",
    "5035": "Code Injection",
    "5034": "Command Execution",
    "9013": "Compliance Policy Violation",
    "20002": "Compliance Violation",
    "3041": "Computer Account Added",
    "3042": "Computer Account Changed",
    "3043": "Computer Account Removed",
    "8083": "Configuration Error",
    "19029": "Configure Activity Attempted",
    "19031": "Configure Activity Failed",
    "19030": "Configure Activity Succeeded",
    "18426": "Content Delivery",
    "7003": "Content Modified By Firewall ",
    "6010": "Content Scan",
    "6011": "Content Scan Failed",
    "6013": "Content Scan Inprogress",
    "6012": "Content Scan Successful",
    "19011": "Create Activity Attempted",
    "19013": "Create Activity Failed",
    "19012": "Create Activity Succeeded",
    "3110": "Creating SA",
    "3112": "Credentials Mismatch",
    "8056": "Critical",
    "8039": "Cron",
    "8041": "Cron Failed",
    "8040": "Cron Status",
    "8042": "Cron Successful",
    "5029": "Cross Site Scripting",
    "12004": "Cross	",
    "15016": "Custom Policy 1",
    "15017": "Custom Policy 2",
    "15018": "Custom Policy 3",
    "15019": "Custom Policy 4",
    "15020": "Custom Policy 5",
    "15021": "Custom Policy 6",
    "15022": "Custom Policy 7",
    "15023": "Custom Policy 8",
    "15024": "Custom Policy 9",
    "15015": "Custom Policy High",
    "15013": "Custom Policy Low",
    "15014": "Custom Policy Medium",
    "10009": "Custom Rule Engine Message	",
    "15004": "Custom Sentry 1",
    "15005": "Custom Sentry 2",
    "15006": "Custom Sentry 3",
    "15007": "Custom Sentry 4",
    "15008": "Custom Sentry 5",
    "15009": "Custom Sentry 6",
    "15010": "Custom Sentry 7",
    "15011": "Custom Sentry 8",
    "15012": "Custom Sentry 9",
    "15003": "Custom Sentry High",
    "15001": "Custom Sentry Low",
    "15002": "Custom Sentry Medium",
    "15028": "Custom User 1",
    "15029": "Custom User 2",
    "15030": "Custom User 3",
    "15031": "Custom User 4",
    "15032": "Custom User 5",
    "15033": "Custom User 6",
    "15034": "Custom User 7",
    "15035": "Custom User 8",
    "15036": "Custom User 9",
    "15027": "Custom User High",
    "15025": "Custom User Low",
    "15026": "Custom User Medium",
    "18409": "DAP Authentication Failed",
    "18410": "DAP Authentication Succeeded",
    "18406": "DAP Session Denied",
    "18405": "DAP Session Ended",
    "18408": "DAP Session In Progress",
    "18404": "DAP Session Started",
    "18407": "DAP Session Status",
    "22018": "DBMS Event",
    "5025": "DHCP Exploit",
    "18384": "DHCP Failure",
    "18380": "DHCP Session Closed",
    "18381": "DHCP Session Denied",
    "18382": "DHCP Session In Progress",
    "18379": "DHCP Session Opened",
    "18383": "DHCP Success",
    "18368": "DNP3 Session Closed",
    "18371": "DNP3 Session Denied",
    "18372": "DNP3 Session In Progress",
    "18367": "DNP3 Session Opened",
    "18369": "DNP3 Session Reset",
    "18370": "DNP3 Session Terminated",
    "18077": "DNS Closed",
    "18082": "DNS Delayed",
    "18080": "DNS Denied",
    "5003": "DNS Exploit",
    "18081": "DNS In Progress",
    "18076": "DNS Opened",
    "7016": "DNS Protocol Anomaly",
    "1010": "DNS Reconnaissance ",
    "18083": "DNS Redirected",
    "18078": "DNS Reset",
    "2005": "DNS Service DoS",
    "18079": "DNS Terminated",
    "8043": "Daemon",
    "8045": "Daemon Failed",
    "8044": "Daemon Status",
    "8046": "Daemon Successful",
    "7060": "Darknet Address",
    "19004": "Data Dump",
    "19005": "Data Import",
    "20013": "Data Loss Possible",
    "9020": "Data Loss Prevention Policy Violation",
    "19006": "Data Selection",
    "18427": "Data Transfer",
    "19007": "Data Truncation",
    "19008": "Data Update",
    "18428": "Data Warehousing",
    "4029": "Database Action Allowed",
    "4030": "Database Action Denied",
    "18092": "Database Closed",
    "18095": "Database Denied",
    "2012": "Database DoS",
    "5021": "Database Exploit",
    "18096": "Database In Progress",
    "3076": "Database Login Failed",
    "3075": "Database Login Succeeded",
    "18091": "Database Opened",
    "9008": "Database Policy Violation",
    "1013": "Database Reconnaissance",
    "18097": "Database Redirected",
    "18093": "Database Reset",
    "18094": "Database Terminated",
    "3096": "Deauthenticating host failed",
    "3095": "Deauthenticating host succeeded",
    "8057": "Debug",
    "19020": "Delete Activity Attempted",
    "19022": "Delete Activity Failed",
    "19021": "Delete Activity Succeeded",
    "3109": "Deleting SA",
    "19032": "Deploy Activity Attempted",
    "19034": "Deploy Activity Failed",
    "19033": "Deploy Activity Succeeded",
    "22003": "Device Audit",
    "22002": "Device Communication",
    "22006": "Device Configuration",
    "22012": "Device Error",
    "22004": "Device Event",
    "22009": "Device Import",
    "22010": "Device Information",
    "22005": "Device Ping",
    "22001": "Device Read",
    "22007": "Device Registration",
    "22008": "Device Route",
    "22027": "Device Tamper Detection",
    "22011": "Device Warning",
    "18429": "Directory Services",
    "19035": "Disable Activity Attempted",
    "19037": "Disable Activity Failed",
    "19036": "Disable Activity Succeeded",
    "19065": "Disable Logging Attempted",
    "19067": "Disable Logging Failed",
    "19066": "Disable Logging Success",
    "3104": "Disassociating host failed",
    "3103": "Disassociating host succeeded",
    "18374": "Discard Session Closed",
    "18377": "Discard Session Denied",
    "18378": "Discard Session In Progress",
    "18373": "Discard Session Opened",
    "18375": "Discard Session Reset",
    "18376": "Discard Session Terminated",
    "2008": "Distributed DoS",
    "2032": "Distributed High Rate DoS",
    "2031": "Distributed High Rate ICMP DoS",
    "2029": "Distributed High Rate TCP DoS",
    "2030": "Distributed High Rate UDP DoS",
    "2040": "Distributed Low Rate DoS",
    "2039": "Distributed Low Rate ICMP DoS",
    "2037": "Distributed Low Rate TCP DoS",
    "2038": "Distributed Low Rate UDP DoS",
    "2036": "Distributed Medium Rate DoS",
    "2035": "Distributed Medium Rate ICMP DoS",
    "2033": "Distributed Medium Rate TCP DoS",
    "2034": "Distributed Medium Rate UDP DoS",
    "4009": "Dynamic Address Translation Successful",
    "18358": "Echo Session Closed",
    "18359": "Echo Session Denied",
    "18360": "Echo Session In Progress",
    "18357": "Echo Session Opened",
    "8061": "Emergency",
    "14017": "Empty Packet Flows",
    "19038": "Enable Activity Attempted",
    "19040": "Enable Activity Failed",
    "19039": "Enable Activity Succeeded",
    "19062": "Enable Logging Attempted",
    "19064": "Enable Logging Failed",
    "19063": "Enable Logging Success",
    "8066": "Encryption protocol configuration mismatch",
    "8055": "Error",
    "12003": "Event Sequence Rule Match",
    "7022": "Executable Code Detected",
    "22022": "Export Event",
    "20003": "Exposed Vulnerability",
    "4031": "FTP Action Allowed",
    "4032": "FTP Action Denied",
    "18011": "FTP Closed",
    "18014": "FTP Denied",
    "2013": "FTP DoS",
    "5015": "FTP Exploit",
    "18015": "FTP In Progress",
    "3020": "FTP Login Failed",
    "3019": "FTP Login Succeeded",
    "3061": "FTP Logout",
    "18010": "FTP Opened",
    "7017": "FTP Protocol Anomaly",
    "1022": "FTP Reconnaissance",
    "18016": "FTP Redirected",
    "18012": "FTP Reset",
    "8063": "FTP Status",
    "18013": "FTP Terminated",
    "9019": "Failed",
    "8023": "Failed Application Modification",
    "8024": "Failed Configuration Modification",
    "8021": "Failed File Modification",
    "8020": "Failed Host	",
    "8019": "Failed Registry Modification",
    "8025": "Failed Service Modification",
    "8022": "Failed Stack Modification",
    "8028": "File Created",
    "8033": "File Deleted",
    "18430": "File Print",
    "18431": "File Transfer",
    "18068": "FileTransfer Closed",
    "18073": "FileTransfer Delayed",
    "18071": "FileTransfer Denied",
    "18072": "FileTransfer In Progress",
    "18067": "FileTransfer Opened",
    "18074": "FileTransfer Queued",
    "18075": "FileTransfer Redirected",
    "18069": "FileTransfer Reset",
    "18070": "FileTransfer Terminated",
    "18352": "Finger Session Closed",
    "18355": "Finger Session Denied",
    "18356": "Finger Session In Progress",
    "18351": "Finger Session Opened",
    "18353": "Finger Session Reset",
    "18354": "Finger Session Terminated",
    "4003": "Firewall Deny",
    "4002": "Firewall Permit",
    "4008": "Firewall Session Closed",
    "4007": "Firewall Session Opened",
    "2054": "Flood",
    "4004": "Flow Context Response",
    "5030": "Format String Vulnerability",
    "20016": "Fraud",
    "18346": "GIOP Session Closed",
    "18349": "GIOP Session Denied",
    "18350": "GIOP Session In Progress",
    "18345": "GIOP Session Opened",
    "18347": "GIOP Session Reset",
    "18348": "GIOP Session Terminated",
    "18418": "Game Session Closed",
    "18421": "Game Session Denied",
    "18422": "Game Session In Progress",
    "18419": "Game Session Reset",
    "18417": "Game Session Started",
    "18420": "Game Session Terminated",
    "18432": "Games",
    "9011": "Games Policy Violation",
    "22024": "Gateway Status",
    "19001": "General Audit Event",
    "3047": "General Authentication Failed",
    "3046": "General Authentication Successful",
    "18340": "Gopher Session Closed",
    "18343": "Gopher Session Denied",
    "18344": "Gopher Session In Progress",
    "18339": "Gopher Session Opened",
    "18341": "Gopher Session Reset",
    "18342": "Gopher Session Terminated",
    "7071": "Government Agency Address",
    "3038": "Group Added",
    "3039": "Group Changed",
    "3036": "Group Member Added",
    "3037": "Group Member Removed",
    "3040": "Group Removed",
    "18334": "Groupwise Session Closed",
    "18337": "Groupwise Session Denied",
    "18338": "Groupwise Session In Progress",
    "18333": "Groupwise Session Opened",
    "18335": "Groupwise Session Reset",
    "18336": "Groupwise Session Terminated",
    "18018": "HTTP Closed",
    "18023": "HTTP Delayed",
    "18021": "HTTP Denied",
    "18022": "HTTP In Progress",
    "18017": "HTTP Opened",
    "18026": "HTTP Proxy",
    "18024": "HTTP Queued",
    "18025": "HTTP Redirected",
    "18019": "HTTP Reset",
    "18020": "HTTP Terminated",
    "18028": "HTTPS Closed",
    "18033": "HTTPS Delayed",
    "18031": "HTTPS Denied",
    "18032": "HTTPS In Progress",
    "18027": "HTTPS Opened",
    "18036": "HTTPS Proxy",
    "18034": "HTTPS Queued",
    "18035": "HTTPS Redirected",
    "18029": "HTTPS Reset",
    "18030": "HTTPS Terminated",
    "18433": "Healthcare",
    "22032": "Heartbeat",
    "2020": "High Rate DoS",
    "2019": "High Rate ICMP DoS",
    "2043": "High Rate ICMP Scan",
    "2044": "High Rate Scan",
    "2017": "High Rate TCP DoS",
    "2041": "High Rate TCP Scan",
    "2018": "High Rate UDP DoS",
    "2042": "High Rate UDP Scan",
    "14020": "High number of Empty Packet Flows",
    "14024": "High number of Large Payload Flows",
    "14004": "High number of Unidirectional Flows",
    "14012": "High number of Unidirectional ICMP Flows",
    "14008": "High number of Unidirectional TCP Flows",
    "3003": "Host Login Failed",
    "3002": "Host Login Succeeded ",
    "3056": "Host Logout ",
    "1008": "Host Port Scan ",
    "1003": "Host Query ",
    "8027": "Host	",
    "8032": "Host	",
    "7053": "Hostile IP",
    "6003": "Hostile Mail Attachment ",
    "6005": "Hostile Software Download",
    "8071": "Hot standby association lost",
    "8069": "Hot standby disable failed",
    "8068": "Hot standby enable failed",
    "8070": "Hot standby enabled successfully",
    "18328": "ICCP Session Closed",
    "18331": "ICCP Session Denied",
    "18332": "ICCP Session In Progress",
    "18327": "ICCP Session Opened",
    "18329": "ICCP Session Reset",
    "18330": "ICCP Session Terminated",
    "18449": "ICMP",
    "2002": "ICMP DoS ",
    "5022": "ICMP Exploit",
    "2057": "ICMP Flood",
    "1017": "ICMP Host Query",
    "1014": "ICMP Reconnaissance",
    "7015": "IDS Evasion ",
    "18316": "IEC 104 Session Closed",
    "18319": "IEC 104 Session Denied",
    "18320": "IEC 104 Session In Progress",
    "18315": "IEC 104 Session Opened",
    "18317": "IEC 104 Session Reset",
    "18318": "IEC 104 Session Terminated",
    "3077": "IKE Authentication Failed",
    "3078": "IKE Authentication Succeeded",
    "3081": "IKE Error",
    "3080": "IKE Session Ended",
    "3079": "IKE Session Started",
    "3082": "IKE Status",
    "9016": "IM Policy Violation",
    "18159": "IM Session Closed",
    "18164": "IM Session Delayed",
    "18162": "IM Session Denied",
    "18163": "IM Session In Progress",
    "18158": "IM Session Opened",
    "18165": "IM Session Redirected",
    "18160": "IM Session Reset",
    "18161": "IM Session Terminated",
    "22016": "IMU Event",
    "9006": "IP Access Policy Violation",
    "7013": "IP Fragmentation ",
    "7032": "IP Protocol Anomaly",
    "7012": "IP Spoof ",
    "4006": "IPS Deny",
    "4039": "IPS Permit",
    "18152": "IPSec Authentication Failed",
    "18153": "IPSec Authentication Succeeded",
    "18156": "IPSec Error",
    "18155": "IPSec Session Ended",
    "18154": "IPSec Session Started",
    "18157": "IPSec Status",
    "9015": "IRC Policy Violation",
    "18310": "IRC Session Closed",
    "18313": "IRC Session Denied",
    "18314": "IRC Session In Progress",
    "18309": "IRC Session Opened",
    "18311": "IRC Session Reset",
    "18312": "IRC Session Terminated",
    "9004": "IRC/IM Policy Violation",
    "18322": "Ident Session Closed",
    "18325": "Ident Session Denied",
    "18326": "Ident Session In Progress",
    "18321": "Ident Session Opened",
    "18323": "Ident Session Reset",
    "18324": "Ident Session Terminated",
    "3120": "Identity Granted",
    "3121": "Identity Removed",
    "3122": "Identity Revoked",
    "7048": "Illegal ICMP Code",
    "7045": "Illegal ICMP Protocol Usage",
    "7047": "Illegal ICMP Type",
    "7043": "Illegal TCP Flag Combination",
    "22019": "Import Event",
    "8052": "Information",
    "7024": "Information Leak",
    "2014": "Infrastructure DoS",
    "5009": "Infrastructure Exploit",
    "18434": "Inner System",
    "5031": "Input Validation Exploit",
    "18435": "Internet Protocol",
    "7064": "Invalid Cert",
    "7004": "Invalid Command or Data ",
    "7034": "Invalid IP Protocol Usage",
    "8078": "Invalid License",
    "7035": "Invalid Protocol",
    "22025": "Job Event",
    "18304": "Kerberos Session Closed",
    "18307": "Kerberos Session Denied",
    "18308": "Kerberos Session In Progress",
    "18303": "Kerberos Session Opened",
    "18305": "Kerberos Session Reset",
    "18306": "Kerberos Session Terminated",
    "8047": "Kernel",
    "8049": "Kernel Failed",
    "8048": "Kernel Status",
    "8050": "Kernel Successful",
    "6014": "Keylogger",
    "7055": "Known Offender IP",
    "18144": "LDAP Authentication Failed",
    "18145": "LDAP Authentication Succeeded",
    "18142": "LDAP Session Denied",
    "18141": "LDAP Session Ended",
    "18140": "LDAP Session Started",
    "18143": "LDAP Session Status",
    "18292": "LPD Session Closed",
    "18295": "LPD Session Denied",
    "18296": "LPD Session In Progress",
    "18291": "LPD Session Opened",
    "18293": "LPD Session Reset",
    "18294": "LPD Session Terminated",
    "14033": "Large Data Transfer",
    "14034": "Large Data Transfer outbound",
    "14021": "Large Payload Flows",
    "18436": "Legacy",
    "8081": "License Error",
    "8085": "License Exceeded",
    "8079": "License Expired",
    "8082": "License Status",
    "5005": "Linux Exploit",
    "20005": "Local Access Vulnerability",
    "22020": "Location Import",
    "3018": "Login with username/password defaults failed",
    "3017": "Login with username/password defaults successful",
    "20019": "Loss of Confidentiality",
    "18298": "Lotus Notes Session Closed",
    "18301": "Lotus Notes Session Denied",
    "18302": "Lotus Notes Session In Progress",
    "18297": "Lotus Notes Session Opened",
    "18299": "Lotus Notes Session Reset",
    "18300": "Lotus Notes Session Terminated",
    "2028": "Low Rate DoS",
    "2027": "Low Rate ICMP DoS",
    "2051": "Low Rate ICMP Scan",
    "2052": "Low Rate Scan",
    "2025": "Low Rate TCP DoS",
    "2049": "Low Rate TCP Scan",
    "2026": "Low Rate UDP DoS",
    "2050": "Low Rate UDP Scan",
    "14018": "Low number of Empty Packet Flows",
    "14022": "Low number of Large Payload Flows",
    "14002": "Low number of Unidirectional Flows",
    "14010": "Low number of Unidirectional ICMP Flows",
    "14006": "Low number of Unidirectional TCP Flows",
    "18286": "MODBUS Session Closed",
    "18289": "MODBUS Session Denied",
    "18290": "MODBUS Session In Progress",
    "18285": "MODBUS Session Opened",
    "18287": "MODBUS Session Reset",
    "18288": "MODBUS Session Terminated",
    "18437": "Mail",
    "18002": "Mail Closed",
    "18007": "Mail Delayed",
    "18005": "Mail Denied",
    "5008": "Mail Exploit",
    "18006": "Mail In Progress",
    "18001": "Mail Opened",
    "9014": "Mail Policy Violation",
    "7018": "Mail Protocol Anomaly",
    "18008": "Mail Queued",
    "1005": "Mail Reconnaissance ",
    "18009": "Mail Redirected",
    "18003": "Mail Reset",
    "2007": "Mail Service DoS",
    "3009": "Mail Service Login Failed",
    "3008": "Mail Service Login Succeeded",
    "18004": "Mail Terminated",
    "8072": "Mainmode Initiation Failure",
    "8073": "Mainmode Initiation Succeeded",
    "8074": "Mainmode Status",
    "6004": "Malicious Software ",
    "6018": "Malware Infection",
    "14026": "Many Attackers to one Target Flow",
    "2024": "Medium Rate DoS",
    "2023": "Medium Rate ICMP DoS",
    "2047": "Medium Rate ICMP Scan",
    "2048": "Medium Rate Scan",
    "2021": "Medium Rate TCP DoS",
    "2045": "Medium Rate TCP Scan",
    "2022": "Medium Rate UDP DoS",
    "2046": "Medium Rate UDP Scan",
    "14019": "Medium number of Empty Packet Flows",
    "14023": "Medium number of Large Payload Flows",
    "14003": "Medium number of Unidirectional Flows",
    "14011": "Medium number of Unidirectional ICMP Flows",
    "14007": "Medium number of Unidirectional TCP Flows",
    "5033": "Memory Corruption",
    "8058": "Messages",
    "20011": "Mis	",
    "20012": "Mis	",
    "20010": "Mis	",
    "18438": "Misc",
    "4027": "Misc Application Action Allowed",
    "4028": "Misc Application Action Denied",
    "4011": "Misc Authorization",
    "2009": "Misc DoS",
    "5010": "Misc Exploit",
    "3005": "Misc Login Failed",
    "3004": "Misc Login Succeeded",
    "3057": "Misc Logout",
    "6007": "Misc Malware",
    "4005": "Misc Network Communication Event",
    "9012": "Misc Policy Violation",
    "1011": "Misc Recon Event",
    "7023": "Misc Suspicious Event",
    "8008": "Misc System Event",
    "18403": "Misc VPN",
    "14032": "Misc flow",
    "8088": "Misconfiguration",
    "19041": "Monitor Activity Attempted",
    "19043": "Monitor Activity Failed",
    "19042": "Monitor Activity Succeeded",
    "18439": "Multimedia",
    "18274": "NCP Session Closed",
    "18277": "NCP Session Denied",
    "18278": "NCP Session In Progress",
    "18273": "NCP Session Opened",
    "18275": "NCP Session Reset",
    "18276": "NCP Session Terminated",
    "18268": "NFS Session Closed",
    "18271": "NFS Session Denied",
    "18272": "NFS Session In Progress",
    "18267": "NFS Session Opened",
    "18269": "NFS Session Reset",
    "18270": "NFS Session Terminated",
    "22014": "NIC Event",
    "1019": "NMAP Reconnaissance",
    "18262": "NNTP Session Closed",
    "18265": "NNTP Session Denied",
    "18266": "NNTP Session In Progress",
    "18261": "NNTP Session Opened",
    "18263": "NNTP Session Reset",
    "18264": "NNTP Session Terminated",
    "5018": "NOOP Exploit",
    "18256": "NTP Session Closed",
    "18259": "NTP Session Denied",
    "18260": "NTP Session In Progress",
    "18255": "NTP Session Opened",
    "18257": "NTP Session Reset",
    "18258": "NTP Session Terminated",
    "8064": "NTP Status",
    "23091": "NetBIOS Group Cleaned",
    "23087": "NetBIOS Group Created",
    "23090": "NetBIOS Group Deleted",
    "23092": "NetBIOS Group Moved",
    "23089": "NetBIOS Group Observed",
    "23088": "NetBIOS Group Updated",
    "18280": "NetBIOS Session Closed",
    "18283": "NetBIOS Session Denied",
    "18284": "NetBIOS Session In Progress",
    "18279": "NetBIOS Session Opened",
    "18281": "NetBIOS Session Reset",
    "18282": "NetBIOS Session Terminated",
    "14028": "Netflow Record",
    "18440": "Network Management",
    "1004": "Network Sweep ",
    "9009": "Network Threshold Policy Violation",
    "17001": "New Host Discovered",
    "8080": "New License Applied",
    "17002": "New OS Discovered",
    "17003": "New Port Discovered",
    "17004": "New Vuln Discovered",
    "20015": "No Password",
    "4036": "No Rate Limiting",
    "4010": "No Translation Group Found",
    "8053": "Notice",
    "4033": "Object Cached",
    "4034": "Object Not Cached",
    "12005": "Offense Rule Match",
    "14025": "One Attacker to Many Target Flow",
    "20006": "Open Wireless Access",
    "7014": "Overlapping IP Fragments ",
    "18441": "P2P",
    "18117": "P2P Closed",
    "18120": "P2P Denied",
    "18121": "P2P In Progress",
    "18116": "P2P Opened",
    "9005": "P2P Policy Violation",
    "18118": "P2P Reset",
    "18119": "P2P Terminated",
    "4038": "PII Access Denied",
    "4037": "PII Access Permitted",
    "14031": "Packeteer Record",
    "3033": "Password Change Failed",
    "3034": "Password Change Succeeded",
    "5014": "Password Guess/Retrieve",
    "8087": "Performance Degradation",
    "8086": "Performance Status",
    "3029": "Policy Added",
    "3030": "Policy Change",
    "20001": "Policy Exposure",
    "21001": "Policy Monitor",
    "20020": "Policy Monitor Risk Score Accumulation",
    "3123": "Policy Removed",
    "9010": "Porn Policy Violation",
    "1007": "Portmap / RPC Request ",
    "20017": "Possible DoS Target",
    "20018": "Possible DoS Weakness",
    "13012": "Potential Botnet connection",
    "13002": "Potential Buffer Overflow",
    "13003": "Potential DNS Exploit",
    "7029": "Potential DNS Vulnerability",
    "7031": "Potential Database Vulnerability",
    "7027": "Potential FTP Vulnerability",
    "13009": "Potential Infrastructure Exploit",
    "13005": "Potential Linux Exploit",
    "13008": "Potential Mail Exploit",
    "7025": "Potential Mail Vulnerability",
    "13010": "Potential Misc Exploit",
    "7038": "Potential NFS Vulnerability",
    "7039": "Potential NNTP Vulnerability",
    "7040": "Potential RPC Vulnerability",
    "7030": "Potential SMB Vulnerability",
    "7042": "Potential SNMP Vulnerability",
    "7028": "Potential SSH Vulnerability",
    "13004": "Potential Telnet Exploit",
    "7041": "Potential Telnet Vulnerability",
    "13006": "Potential Unix Exploit",
    "7026": "Potential Version Vulnerability",
    "7057": "Potential VoIP Vulnerability",
    "13011": "Potential Web Exploit",
    "7010": "Potential Web Vulnerability ",
    "13007": "Potential Windows Exploit",
    "13013": "Potential worm activity",
    "22030": "Power Outage",
    "22031": "Power Restoration",
    "8059": "Privilege Access",
    "3006": "Privilege Escalation Failed",
    "3007": "Privilege Escalation Succeeded",
    "19009": "Procedure/Trigger Execution",
    "14029": "QFlow Record",
    "6017": "Quarantine Failed",
    "6016": "Quarantine Successful",
    "8075": "Quickmode Initiation Failure",
    "8076": "Quickmode Initiation Succeeded",
    "8077": "Quickmode Status",
    "3087": "RADIUS Authentication Failed",
    "3088": "RADIUS Authentication Succeeded",
    "3085": "RADIUS Session Denied",
    "3084": "RADIUS Session Ended",
    "3083": "RADIUS Session Started",
    "3086": "RADIUS Session Status",
    "18061": "RDP Closed",
    "18064": "RDP Denied",
    "18065": "RDP In Progress",
    "18060": "RDP Opened",
    "18066": "RDP Redirected",
    "18062": "RDP Reset",
    "18063": "RDP Terminated",
    "18244": "REXEC Session Closed",
    "18247": "REXEC Session Denied",
    "18248": "REXEC Session In Progress",
    "18243": "REXEC Session Opened",
    "18245": "REXEC Session Reset",
    "18246": "REXEC Session Terminated",
    "7056": "RFC 1918 (private) IP",
    "18238": "RLOGIN Session Closed",
    "18241": "RLOGIN Session Denied",
    "18242": "RLOGIN Session In Progress",
    "18237": "RLOGIN Session Opened",
    "18239": "RLOGIN Session Reset",
    "18240": "RLOGIN Session Terminated",
    "1009": "RPC Dump ",
    "5016": "RPC Exploit",
    "18250": "RPC Session Closed",
    "18253": "RPC Session Denied",
    "18254": "RPC Session In Progress",
    "18249": "RPC Session Opened",
    "18251": "RPC Session Reset",
    "18252": "RPC Session Terminated",
    "18232": "RSH Session Closed",
    "18235": "RSH Session Denied",
    "18236": "RSH Session In Progress",
    "18231": "RSH Session Opened",
    "18233": "RSH Session Reset",
    "18234": "RSH Session Terminated",
    "18228": "RUSERS Session Closed",
    "18229": "RUSERS Session Denied",
    "18230": "RUSERS Session In Progress",
    "18227": "RUSERS Session Opened",
    "4035": "Rate Limiting",
    "19014": "Read Activity Attempted",
    "19016": "Read Activity Failed",
    "19015": "Read Activity Succeeded",
    "19056": "Receive Activity Attempted",
    "19058": "Receive Activity Failed",
    "19057": "Receive Activity Succeeded",
    "8026": "Registry Addition",
    "8031": "Registry Deletion",
    "22013": "Relay Event",
    "18362": "Remote .NET Session Closed",
    "18365": "Remote .NET Session Denied",
    "18366": "Remote .NET Session In Progress",
    "18361": "Remote .NET Session Opened",
    "18363": "Remote .NET Session Reset",
    "18364": "Remote .NET Session Terminated",
    "18442": "Remote Access",
    "5026": "Remote Access Exploit",
    "3045": "Remote Access Login Failed",
    "3044": "Remote Access Login Succeeded",
    "3063": "Remote Access Logout",
    "9003": "Remote Access Policy Violation",
    "20004": "Remote Access Vulnerability",
    "5032": "Remote Code Execution",
    "22033": "Remote Connection Event",
    "22023": "Remote Signalling",
    "18044": "RemoteAccess Closed",
    "18049": "RemoteAccess Delayed",
    "18047": "RemoteAccess Denied",
    "18048": "RemoteAccess In Progress",
    "18043": "RemoteAccess Opened",
    "18050": "RemoteAccess Redirected",
    "18045": "RemoteAccess Reset",
    "18046": "RemoteAccess Terminated",
    "6020": "Remove Failed",
    "6019": "Remove Successful",
    "5036": "Replay Attack",
    "19044": "Restore Activity Attempted",
    "19046": "Restore Activity Failed",
    "19045": "Restore Activity Succeeded",
    "16010": "Risk Manager Configuration",
    "7070": "Rogue device detected",
    "22021": "Route Import",
    "7068": "Route Poisoning",
    "7019": "Routing Protocol Anomaly",
    "18443": "Routing Protocols",
    "3106": "SA Creation Failure",
    "3105": "SA Error",
    "3107": "SA Established",
    "3108": "SA Rejected",
    "3118": "SFTP Login Failed",
    "3117": "SFTP Login Succeeded",
    "3119": "SFTP Logout",
    "14030": "SFlow Record",
    "16002": "SIM Configuration Change",
    "16003": "SIM User Action",
    "16001": "SIM User Authentication",
    "18216": "SMB Session Closed",
    "18219": "SMB Session Denied",
    "18220": "SMB Session In Progress",
    "18215": "SMB Session Opened",
    "18217": "SMB Session Reset",
    "18218": "SMB Session Terminated",
    "18099": "SMTP Closed",
    "18104": "SMTP Delayed",
    "18102": "SMTP Denied",
    "18103": "SMTP In Progress",
    "18098": "SMTP Opened",
    "18105": "SMTP Queued",
    "18106": "SMTP Redirected",
    "18100": "SMTP Reset",
    "18101": "SMTP Terminated",
    "5017": "SNMP Exploit",
    "1016": "SNMP Reconnaissance",
    "18212": "SNMP Session Closed",
    "18213": "SNMP Session Denied",
    "18214": "SNMP Session In Progress",
    "18211": "SNMP Session Opened",
    "8062": "SNMP Status",
    "5028": "SQL Injection",
    "7021": "SQL Protocol Anomaly",
    "18038": "SSH Closed",
    "18041": "SSH Denied",
    "5020": "SSH Exploit",
    "18042": "SSH In Progress",
    "3022": "SSH Login Failed",
    "3021": "SSH Login Succeeded",
    "3062": "SSH Logout",
    "18037": "SSH Opened",
    "18039": "SSH Reset",
    "3072": "SSH Session Finished",
    "3071": "SSH Session Started",
    "18040": "SSH Terminated",
    "18206": "SSL Session Closed",
    "18209": "SSL Session Denied",
    "18210": "SSL Session In Progress",
    "18205": "SSL Session Opened",
    "18207": "SSL Session Reset",
    "18208": "SSL Session Terminated",
    "2062": "SYN ACK Flood",
    "2061": "SYN FIN Flood",
    "2058": "SYN Flood",
    "2060": "SYN URG Flood",
    "5019": "Samba Exploit",
    "3052": "Samba Login Failed",
    "3051": "Samba Login Succeeded",
    "3065": "Samba Logout",
    "19010": "Schema Change",
    "22026": "Security Event",
    "18444": "Security Protocol",
    "19059": "Send Activity Attempted",
    "19061": "Send Activity Failed",
    "19060": "Send Activity Succeeded",
    "8084": "Service Disruption",
    "8011": "Service Failure",
    "8030": "Service Installed",
    "8009": "Service Started",
    "8010": "Service Stopped",
    "8035": "Service Uninstalled",
    "16009": "Session Authentication Expired",
    "16008": "Session Authentication Invalid",
    "4017": "Session Closed",
    "16004": "Session Created",
    "4022": "Session Delayed",
    "4020": "Session Denied",
    "16005": "Session Destroyed",
    "5012": "Session Hijack",
    "4021": "Session In Progress",
    "4024": "Session Inbound",
    "4016": "Session Opened",
    "4025": "Session Outbound",
    "4023": "Session Queued",
    "4018": "Session Reset",
    "4019": "Session Terminated",
    "21003": "Simulations",
    "12002": "Single Event Rule Match",
    "6009": "Spyware Detected",
    "19047": "Start Activity Attempted",
    "19049": "Start Activity Failed",
    "19048": "Start Activity Succeeded",
    "3100": "Station association failed",
    "3099": "Station association succeeded",
    "3098": "Station authentication failed",
    "3097": "Station authentication succeeded",
    "3102": "Station reassociation failed",
    "3101": "Station reassociation succeeded",
    "19050": "Stop Activity Attempted",
    "19052": "Stop Activity Failed",
    "19051": "Stop Activity Succeeded",
    "10008": "Stored",
    "18445": "Streaming",
    "18222": "Streaming Media Session Closed",
    "18225": "Streaming Media Session Denied",
    "18226": "Streaming Media Session In Progress",
    "18221": "Streaming Media Session Opened",
    "18223": "Streaming Media Session Reset",
    "18224": "Streaming Media Session Terminated",
    "9018": "Succeeded",
    "8016": "Successful Application Modification",
    "8017": "Successful Configuration Modification",
    "8014": "Successful File Modification",
    "8013": "Successful Host	",
    "8012": "Successful Registry Modification",
    "8018": "Successful Service Modification",
    "8015": "Successful Stack Modification",
    "7006": "Suspicious Activity ",
    "7062": "Suspicious Address",
    "7067": "Suspicious BGP Activity ",
    "22029": "Suspicious Behavior",
    "7007": "Suspicious File Name",
    "14016": "Suspicious Flow",
    "7037": "Suspicious ICMP Activity",
    "7050": "Suspicious ICMP Code",
    "14013": "Suspicious ICMP Flow",
    "7046": "Suspicious ICMP Protocol Usage",
    "7049": "Suspicious ICMP Type",
    "7033": "Suspicious IP Address",
    "7005": "Suspicious Packet ",
    "3050": "Suspicious Password",
    "7002": "Suspicious Pattern Detected ",
    "7008": "Suspicious Port Activity ",
    "7066": "Suspicious Protocol Usage",
    "7009": "Suspicious Routing ",
    "7044": "Suspicious TCP Flag Combination",
    "14015": "Suspicious TCP Flow",
    "14014": "Suspicious UDP Flow",
    "3016": "Suspicious Username",
    "7036": "Suspicious Windows Events",
    "18202": "Syslog Session Closed",
    "18203": "Syslog Session Denied",
    "18204": "Syslog Session In Progress",
    "18201": "Syslog Session Opened",
    "8037": "System Action Allow",
    "8038": "System Action Deny",
    "8002": "System Boot ",
    "8003": "System Configuration ",
    "8007": "System Error",
    "8005": "System Failure ",
    "8004": "System Halt ",
    "8036": "System Informational",
    "3027": "System Security Access Granted",
    "3028": "System Security Access Removed",
    "8006": "System Status ",
    "3094": "TACACS Authentication Failed",
    "3093": "TACACS Authentication Succeeded",
    "3091": "TACACS Session Denied",
    "3090": "TACACS Session Ended",
    "3089": "TACACS Session Started",
    "3092": "TACACS Session Status",
    "2003": "TCP DoS",
    "2055": "TCP Flood",
    "7051": "TCP Port 0",
    "1020": "TCP Reconnaissance",
    "18184": "TFTP Session Closed",
    "18187": "TFTP Session Denied",
    "18188": "TFTP Session In Progress",
    "18183": "TFTP Session Opened",
    "18185": "TFTP Session Reset",
    "18186": "TFTP Session Terminated",
    "18178": "TN3270 Session Closed",
    "18181": "TN3270 Session Denied",
    "18182": "TN3270 Session In Progress",
    "18177": "TN3270 Session Opened",
    "18179": "TN3270 Session Reset",
    "18180": "TN3270 Session Terminated",
    "18412": "TOR Session Closed",
    "18415": "TOR Session Denied",
    "18416": "TOR Session In Progress",
    "18413": "TOR Session Reset",
    "18411": "TOR Session Started",
    "18414": "TOR Session Terminated",
    "2015": "Telnet DoS",
    "5004": "Telnet Exploit",
    "3049": "Telnet Login Failed",
    "3048": "Telnet Login Succeeded",
    "3064": "Telnet Logout",
    "18190": "Telnet Session Closed",
    "18193": "Telnet Session Denied",
    "18194": "Telnet Session In Progress",
    "18189": "Telnet Session Opened",
    "18191": "Telnet Session Reset",
    "18192": "Telnet Session Terminated",
    "11002": "Threshold",
    "22028": "Time Event",
    "21002": "Topology",
    "18174": "Traceroute Session Closed",
    "18175": "Traceroute Session Denied",
    "18176": "Traceroute Session In Progress",
    "18173": "Traceroute Session Opened",
    "6008": "Trojan Detected",
    "3025": "Trusted Domain Added",
    "3026": "Trusted Domain Removed",
    "2004": "UDP DoS",
    "5023": "UDP Exploit",
    "2056": "UDP Flood",
    "1018": "UDP Host Query",
    "7052": "UDP Port 0",
    "1015": "UDP Reconnaissance",
    "22015": "UIQ Event",
    "2059": "URG Flood",
    "20009": "Un	",
    "20008": "Un	",
    "4026": "Unauthorized Access Attempt",
    "18446": "Uncommon Protocol",
    "19053": "Undeploy Activity Attempted",
    "19055": "Undeploy Activity Failed",
    "19054": "Undeploy Activity Succeeded",
    "14001": "Unidirectional Flow",
    "14009": "Unidirectional ICMP Flow",
    "14005": "Unidirectional TCP Flow",
    "2010": "Unix DOS",
    "5006": "Unix Exploit",
    "1021": "Unix Reconnaissance",
    "10001": "Unknown ",
    "3001": "Unknown Authentication",
    "12001": "Unknown CRE Event",
    "2001": "Unknown DoS Attack",
    "10003": "Unknown Dragon Event",
    "7011": "Unknown Evasion Event ",
    "5001": "Unknown Exploit Attack",
    "14027": "Unknown Flow",
    "1001": "Unknown Form of Recon",
    "6001": "Unknown Malware ",
    "4001": "Unknown Network Communication Event",
    "10007": "Unknown Nortel Event",
    "10004": "Unknown Pix Firewall Event",
    "9001": "Unknown Policy Violation",
    "13001": "Unknown Potential Exploit Attack",
    "10002": "Unknown Snort Event",
    "7001": "Unknown Suspicious Event",
    "8001": "Unknown System Event",
    "10005": "Unknown Tipping Point Event",
    "10006": "Unknown Windows Auth Server Event",
    "19017": "Update Activity Attempted",
    "19019": "Update Activity Failed",
    "19018": "Update Activity Succeeded",
    "3031": "User Account Added",
    "3032": "User Account Changed",
    "3126": "User Account Expired",
    "3124": "User Account Locked",
    "3035": "User Account Removed",
    "3125": "User Account Unlocked",
    "7065": "User Activity",
    "3114": "User Login Attempt",
    "3116": "User Login Failure",
    "3115": "User Login Success",
    "3023": "User Right Assigned",
    "3024": "User Right Removed",
    "18052": "VPN Closed",
    "18057": "VPN Delayed",
    "18055": "VPN Denied",
    "18056": "VPN In Progress",
    "18051": "VPN Opened",
    "18058": "VPN Queued",
    "18059": "VPN Redirected",
    "18053": "VPN Reset",
    "18054": "VPN Terminated",
    "6006": "Virus Detected",
    "18447": "VoIP",
    "18133": "VoIP Closed",
    "18138": "VoIP Delayed",
    "18136": "VoIP Denied",
    "2053": "VoIP DoS",
    "14035": "VoIP Flows",
    "18137": "VoIP In Progress",
    "3067": "VoIP Login Failed",
    "3068": "VoIP Login Logout",
    "3066": "VoIP Login Succeeded",
    "18132": "VoIP Opened",
    "9017": "VoIP Policy Violation",
    "18139": "VoIP Redirected",
    "18134": "VoIP Reset",
    "3069": "VoIP Session Initiated",
    "3070": "VoIP Session Terminated",
    "18135": "VoIP Terminated",
    "8054": "Warning",
    "7054": "Watch List IP",
    "7059": "Watchlist Address",
    "9021": "Watchlist Object",
    "20014": "Weak Authentication",
    "20007": "Weak Encryption",
    "18448": "Web",
    "18123": "Web Closed",
    "18128": "Web Delayed",
    "18126": "Web Denied",
    "5011": "Web Exploit",
    "18127": "Web In Progress",
    "18122": "Web Opened",
    "9022": "Web Policy Allow",
    "9002": "Web Policy Violation",
    "7020": "Web Protocol Anomaly",
    "18131": "Web Proxy",
    "18129": "Web Queued",
    "1012": "Web Reconnaissance",
    "18130": "Web Redirected",
    "18124": "Web Reset",
    "2006": "Web Service DoS",
    "3013": "Web Service Login Failed",
    "3012": "Web Service Login Succeeded",
    "3059": "Web Service Logout",
    "18125": "Web Terminated",
    "18167": "Whois Session Closed",
    "18170": "Whois Session Denied",
    "18171": "Whois Session In Progress",
    "18166": "Whois Session Opened",
    "18172": "Whois Session Redirected",
    "18168": "Whois Session Reset",
    "18169": "Whois Session Terminated",
    "2011": "Windows DoS",
    "5007": "Windows Exploit",
    "1006": "Windows Reconnaissance",
    "5013": "Worm Active"
}
DEFAULT_CATEGORY = 'DEFAULT'
QRADAR_SOURCE_TYPE = 'QRadar'
FIRST_TIME_RUN_OFFSET_IN_DAYS = 1
EVENTS_COUNT_FILE_NAME = "offenses_events_count.json"
REFETCHING_OFFENSES_FILE_NAME = "refetching_offenses.json"
REFETCHING_TIME_KEY_NAME = "siemplify_refetching_time"
MISSED_OFFENSE_KEY_NAME = "is_missed_offense"
MAX_TIME_FOR_REFETCHING = 5  # minutes
OLD_OFFENSE_SHIFT = 60  # minutes


# =====================================
#              CLASSES                #
# =====================================
class QRadarCorrelationsEventsConnectorException(Exception):
    """
    QRadar Correlations Events Connector Exception
    """
    pass


class QRadarCorrelationsEventsConnector(object):
    """
    QRadar Correlations Events Connector
    """

    def __init__(self, connector_scope):
        self.logger = connector_scope.LOGGER
        self.run_folder = connector_scope.run_folder

    def is_refetching_timeout(self, refetching_time):
        offense_arrow = arrow.get(convert_unixtime_to_datetime(refetching_time))
        return offense_arrow.shift(minutes=MAX_TIME_FOR_REFETCHING) < arrow.utcnow()

    def get_refetching_offenses(self):
        refetching_offenses_file = os.path.join(self.run_folder, REFETCHING_OFFENSES_FILE_NAME)
        if os.path.exists(refetching_offenses_file):
            with open(refetching_offenses_file, 'r') as rf_file:
                rf_offenses = json.loads(rf_file.read())
            # Filter our too old offenses
            return [offense for offense in rf_offenses if
                    not self.is_refetching_timeout(offense[REFETCHING_TIME_KEY_NAME])]

        return []

    def update_refetching_offenses(self, refetching_offenses):
        refetching_offenses_file = os.path.join(self.run_folder, REFETCHING_OFFENSES_FILE_NAME)
        if not os.path.exists(os.path.dirname(refetching_offenses_file)):
            os.makedirs(os.path.dirname(refetching_offenses_file))

        with open(refetching_offenses_file, 'w') as rf_file:
            rf_file.write(json.dumps(refetching_offenses))

    def filter_offenses_by_events_count(self, events_count_file_path, offenses):
        """
        Check for offense events count, get only offenses with new events (local filter)
        :param offenses: {list of dicts}
        :return: {list of dicts}  filtered_offenses
        """
        filtered_offenses = []
        events_count = self.load_events_count_from_file(events_count_file_path)
        for offense in offenses:
            if int(events_count.get(str(offense['id']), 0)) < int(offense.get('event_count', 0)):
                filtered_offenses.append(offense)
                events_count[str(offense['id'])] = int(offense.get('event_count', 0))
        return filtered_offenses

    def load_events_count_from_file(self, events_count_file_path):
        """
        Load events count from local json file
        :return: {dict} ex.-{<offense_id>:<last_events_count>}
        """
        if os.path.exists(events_count_file_path):
            with open(events_count_file_path, 'r') as count_file:
                return json.loads(count_file.read())
        return {}

    def write_events_count_to_file(self, events_count_file_path, events_count_dict):
        """
        Save events count to local json file
        :param events_count_dict: ex.-{<offense_id>:<last_events_count>}
        :return:
        """
        if not os.path.exists(os.path.dirname(events_count_file_path)):
            os.makedirs(os.path.dirname(events_count_file_path))

        with open(events_count_file_path, 'w') as count_file:
            count_file.write(json.dumps(events_count_dict))

    @staticmethod
    def validate_timestamp_offset(time_stamp_unixtime, offset_in_days=2, offset_in_minutes=None):
        """
        Validate if timestamp in offset range.
        :param time_stamp_unixtime: {long}
        :param offset_in_days: {integer}
        :return: unixtime: if time not in offset return offset time {long}
        """
        offset_datetime = utc_now() - datetime.timedelta(days=offset_in_days)
        # Convert offset time to unixtime.
        offset_time_unixtime = convert_datetime_to_unix_time(offset_datetime)

        if time_stamp_unixtime < offset_time_unixtime:
            return offset_time_unixtime

        return time_stamp_unixtime

    @staticmethod
    def calculate_case_priority_by_magnitude(events_list):
        """
        Calculate Siemplify priority.
        :param events_list: list of dicts when each dict is an event {list}
        :return: case priority {integer}
        """
        # Get max magnitude.
        max_magnitude = 0
        for event in events_list:
            if event.get('magnitude', max_magnitude) > max_magnitude:
                max_magnitude = event.get('magnitude', max_magnitude)

        # Match magnitude to Siemplify value.
        if max_magnitude < 2:
            return -1
        elif max_magnitude < 4:
            return 40
        elif max_magnitude < 6:
            return 60
        elif max_magnitude < 8:
            return 80
        return 100

    @staticmethod
    def get_category_human_readable_value(category_id):
        """
        Return human readable value for a category ID.
        :param category_id: event category ID {string}
        :return: human readable category {string}
        """

        return CATEGORY_HUMAN_READABLE.get(category_id, DEFAULT_CATEGORY)

    def create_case_package(self, offense_id, rule_name, events_list, environment=None):
        """
        Create case package.
        :param offense_id: QRadar offense id {string}
        :param rule_name: QRadar rule {string}
        :param events_list: list of dicts when each dict is an event {list}
        :return: Siemplify case object {caseInfo}
        """
        self.logger.info("Creating CaseInfo for {} - {}".format(str(offense_id).encode("utf-8"),
                                                                str(rule_name).encode("utf-8")))

        case_info = CaseInfo()
        #  sort events by start time.
        events_list = sorted(events_list, key=lambda item: item.get('startTime', 1))

        case_info.start_time = int(events_list[0].get("startTime", 1))
        case_info.end_time = int(events_list[-1].get("endTime", 1))
        case_info.description = "Offence ID: {0}, Rule Name: {1}".format(str(offense_id).encode("utf-8"),
                                                                         str(rule_name).encode("utf-8"))
        case_info.ticket_id = "{offense_id}_{rule_name}_{start_time}_{end_time}".format(
            offense_id=str(offense_id).encode("utf-8"),
            rule_name=str(rule_name).encode("utf-8"),
            start_time=case_info.start_time,
            end_time=case_info.end_time)
        case_info.environment = environment
        case_info.display_id = "{0}_{1}".format(case_info.ticket_id, uuid.uuid4())
        case_info.name = rule_name
        case_info.rule_generator = rule_name
        # Qradar cases based on events so there always has to be event at the list.
        case_info.device_product = events_list[0].get("deviceProduct", "Error Getting Device Product")
        case_info.device_vendor = self.get_category_human_readable_value(events_list[0].get('category'))
        case_info.priority = self.calculate_case_priority_by_magnitude(events_list)

        # Add the offense_id and the offense updated time (last event) in order to sync Qradar offenses with Siemplify
        case_info.extensions.update({'offense_id': offense_id})
        case_info.source_grouping_identifier = offense_id

        # Flat events data.
        try:
            case_info.events = list(map(dict_to_flat, events_list))
        except Exception as e:
            self.logger.error("Unable to flatten events: {}".format(str(e)))
            self.logger.exception(e)
            case_info.events = []

        return case_info

    def filter_events_per_rule(self, events, whitelist, events_limit_per_rule):
        """
        Arrage all events in a dict per rule and filter them by the giving whitelist
        :param events: {dict} events to arrange and filter
        :param whitelist: {list} rules to include (if empty all rules will be included)
        :param events_limit_per_rule: {int}
        :return: {dict} events per rule ex.-{<rulename>:[<event1>,<event2>]}
        """
        result_dict = collections.defaultdict(list)

        for event in events:
            self.logger.info("Processing event: {}".format(event.get("EventName", "Can't get event name")))
            rulename_field_name = 'rulename_creEventList' if 'rulename_creEventList' in event else 'rulename_creEventList'.lower()
            for rule in event[rulename_field_name]:
                if len(result_dict[rule]) < events_limit_per_rule:
                    if rule in whitelist or not whitelist:
                        result_dict[rule].append(event)
                        self.logger.info("Add event to caseinfo of rule {}".format(str(rule).encode("utf-8")))
                    else:
                        self.logger.warn(
                            "Event's rule {} not in whitelist. not including event in this rule's caseinfo.".format(
                                str(rule).encode("utf-8")))
                else:
                    self.logger.warn(
                        "Reached event count limit for rule {}. Skipping event.".format(str(rule).encode("utf-8")))

        # Remove empty values
        return {rule: events for rule, events in list(result_dict.items()) if events}


def add_offset_to_unix_time(unixtime_timestamp, offset_in_hours=0):
    """
    Add offset to unixtime timestamp.
    :param unixtime_timestamp: unixtime timestamp {long}
    :param offset_in_hours: offset to add in hours {integer}
    :return: unixtime timestamp {long}
    """
    datetime_timestamp = convert_unixtime_to_datetime(unixtime_timestamp)
    return convert_datetime_to_unix_time(datetime_timestamp - datetime.timedelta(hours=offset_in_hours))


@output_handler
def main_handler(test_handler=False):
    """
    Main hadler for qradar connector
    :param test_handler: run test flow of real flow (timestamp updating is the differencee)
    :return:
    """
    connector_scope = SiemplifyConnectorExecution()
    qradar_connector = QRadarCorrelationsEventsConnector(connector_scope)
    output_variables = {}
    log_items = []
    cases = []
    refetching_offenses = qradar_connector.get_refetching_offenses()

    try:
        if test_handler:
            connector_scope.LOGGER.info(" ------------ Starting Qradar Connector test. ------------ ")

        else:
            connector_scope.LOGGER.info(" ------------ Starting Connector. ------------ ")

        # Parameters.
        api_root = connector_scope.parameters.get('API Root')
        api_token = connector_scope.parameters.get('API Token')
        api_version = connector_scope.parameters.get('API Version')
        custom_fields = connector_scope.parameters.get('Custom Fields', '')
        events_limit_per_offence = int(connector_scope.parameters['Events Limit Per Offense'])
        event_limit_per_rule = int(connector_scope.parameters['Event Limit Per Rule'])
        max_days_backwards = int(connector_scope.parameters.get('Max Days Backwards', 1))
        max_offenses_per_cycle = int(connector_scope.parameters.get('Max Offenses Per Cycle', 1000))
        whitelist = connector_scope.whitelist

        connector_scope.LOGGER.info('Connection to QRadar')
        qradar_manager = QRadarManager(api_root, api_token, api_version)

        # Get successful run time.
        last_success_time = qradar_connector.validate_timestamp_offset(connector_scope.fetch_timestamp(),
                                                                       offset_in_days=max_days_backwards)
        # end time for the event query (AQL STOP query value)
        end_events_query_datetime = utc_now()

        # Get updated offenses.
        connector_scope.LOGGER.info('Starting fetching updated offenses since: {0}'.format(last_success_time))

        try:
            offenses = qradar_manager.get_updated_offenses_from_time(last_success_time)
            connector_scope.LOGGER.info('Found {0} updated offenses with ids: {1}.'.format(len(offenses),
                                                                                           [str(
                                                                                               offense["id"]).encode(
                                                                                               "utf-8") for offense in
                                                                                               offenses]))

        except Exception as err:
            raise QRadarCorrelationsEventsConnectorException(
                'Error fetching updated offenses since {0}, ERROR: {1}'.format(
                    last_success_time,
                    err
                ))

        # Calculate the unixtime of last_success_time - OLD_OFFENSE_SHIFT,
        # but make sure it is non-negative)
        older_success_time = max(arrow.get(last_success_time / 1000).shift(
            minutes=-OLD_OFFENSE_SHIFT).timestamp * 1000, 1)
        connector_scope.LOGGER.info(
            "Fetching older offenses since: {}".format(older_success_time))

        try:
            old_offenses = qradar_manager.get_updated_offenses_from_time(
                older_success_time)

            connector_scope.LOGGER.info(
                'Found {0} older offenses with ids: {1}.'.format(
                    len(old_offenses),
                    [str(
                        offense["id"]).encode(
                        "utf-8") for offense in
                        old_offenses]))

            offenses_ids = [offense["id"] for offense in offenses]

            events_count_file_path = os.path.join(
                connector_scope.run_folder, EVENTS_COUNT_FILE_NAME)

            events_count = qradar_connector.load_events_count_from_file(
                events_count_file_path)

            missed_offenses = []

            for offense in old_offenses:
                if offense["id"] not in offenses_ids:
                    connector_scope.LOGGER.info(
                        "Offense {} not in updated offenses. Checking if missed it before.".format(offense["id"]))
                    # Offense might be a missed one
                    if (str(offense["id"]) not in list(events_count.keys()) and int(
                            offense.get('event_count', 0)) != 0) or \
                            int(events_count.get(str(offense["id"]), 0)) != int(offense.get('event_count', 0)):
                        # The offense is not in events count and its event count is not 0
                        # or its event count was updated since last time.
                        # Offense was missed - add it to missed offenses list
                        connector_scope.LOGGER.info(
                            "Offense {} was missed according to events count file. Saved event count: {}, current "
                            "event count: {}".format(
                                offense["id"], int(events_count.get(str(offense["id"]), 0)),
                                int(offense.get('event_count', 0))))
                        # Mark the offense as missed
                        offense[MISSED_OFFENSE_KEY_NAME] = True
                        missed_offenses.append(offense)

            connector_scope.LOGGER.info(
                'Found {0} missed offenses with ids: {1}.'.format(
                    len(missed_offenses),
                    [str(
                        offense["id"]).encode(
                        "utf-8") for offense in
                        missed_offenses]))

        except Exception as err:
            raise QRadarCorrelationsEventsConnectorException(
                'Error fetching missed offenses since {0}, ERROR: {1}'.format(
                    older_success_time,
                    err
                ))

        # Filter the offenses according to events count and slicing per max_offenses_per_cycle
        try:
            events_count_file_path = os.path.join(connector_scope.run_folder, EVENTS_COUNT_FILE_NAME)
            offenses = qradar_connector.filter_offenses_by_events_count(events_count_file_path, offenses)

            connector_scope.LOGGER.info(
                'Filtered to {0} updated offenses with new events with ids: {1}.'.format(len(offenses),
                                                                                         [str(offense["id"]).encode(
                                                                                             "utf-8") for offense in
                                                                                             offenses]))

            connector_scope.LOGGER.info("Joining missed offenses with filterd updated offenses")
            # Add the missed offenses before the filtered offenses
            offenses = missed_offenses + offenses

            if refetching_offenses:
                connector_scope.LOGGER.info(
                    "Found {} offenses which requires re fetching from qradar, putting them first: {}".format(
                        len(refetching_offenses),
                        [str(offense["id"]).encode(
                            "utf-8") for offense in
                            refetching_offenses]))

                # Filter out duplicate offenses
                # Map refetch offenses to offense id
                refetching_offenses_map = {offense["id"]: offense for offense in refetching_offenses}

                # Filter out the offenses that are duplicate with the refetching iffenses
                offenses_map = {offense["id"]: offense for offense in offenses if
                                offense["id"] not in list(refetching_offenses_map.keys())}

                # join the refetch offenses with the filtered offenses
                offenses = list(refetching_offenses_map.values()) + list(offenses_map.values())

            offenses = offenses[:max_offenses_per_cycle]
            connector_scope.LOGGER.info("Slicing offenses to {0} offenses".format(max_offenses_per_cycle))
            connector_scope.LOGGER.info(
                "Final selected offenses: {}".format([offense.get('id') for offense in offenses]))

        except Exception as err:
            raise QRadarCorrelationsEventsConnectorException(
                'Error filtering updated offenses since {0}, ERROR: {1}'.format(
                    last_success_time,
                    err
                ))

        # Connector time stamp handling
        if offenses:
            # Sort the offenses by last_updated_time
            # Take newest offense update time as the new timestamp
            new_timestamp = sorted(offenses, key=lambda offense: offense.get('last_updated_time', 0))[-1].get(
                'last_updated_time', last_success_time)
        else:
            new_timestamp = last_success_time

        if test_handler:
            if offenses:
                offenses = offenses[:1]

        for offense in offenses:
            offense_id = offense["id"]

            try:
                offense_tenant = qradar_manager.get_domain_name_by_id(
                    offense.get('domain_id')) or connector_scope.context.connector_info.environment
            except Exception as e:
                connector_scope.LOGGER.error(
                    "Unable to resolve domain {}".format(str(offense.get('domain_id')).encode("utf-8")))
                connector_scope.LOGGER.exception(e)
                offense_tenant = connector_scope.context.connector_info.environment

            # Get rules and their events by offense id.
            # Result is a dict where the rules are the keys and the events are the value.
            connector_scope.LOGGER.info(
                'Processing on offense with id: {0}'.format(str(offense_id).encode("utf-8")))
            try:
                if offense.get(MISSED_OFFENSE_KEY_NAME, False):
                    # Offense is a missed one - get its all events from timestamp 1
                    # up to max days backwards
                    offense_last_success_time = 1

                else:
                    # Handle refetching offenses - if REFETCHING_TIME_KEY_NAME in offense keys,
                    # then this is a RF offense, so update the fetching time to the original one.
                    offense_last_success_time = offense.get(
                        REFETCHING_TIME_KEY_NAME, last_success_time)

                    connector_scope.LOGGER.info(
                        "Fetching events for offense {} since: {}".format(offense["id"], offense_last_success_time))

                last_success_time_datetime = convert_unixtime_to_datetime(offense_last_success_time)
                events = qradar_manager.get_events_by_offense_id(offense_id,
                                                                 custom_fields,
                                                                 offense_last_success_time,
                                                                 last_success_time_datetime,
                                                                 end_events_query_datetime,
                                                                 events_limit_per_offence,
                                                                 max_days_backwards)
                if not events:
                    connector_scope.LOGGER.info(
                        "No events found. Added offense {} to refetching list. Last saved event count: {}, "
                        "current event count: {}".format(
                            offense["id"], events_count.get(str(offense["id"])), offense.get("event_count")))
                    # No events - add the offense to the RF offenses list.
                    offense.update({
                        REFETCHING_TIME_KEY_NAME: offense_last_success_time
                    })
                    # If the offense is already in refetching_offenses,
                    # remove the old reference from there.
                    refetching_offenses[:] = [rf_offense for rf_offense in refetching_offenses if
                                              rf_offense['id'] != offense_id]
                    # Re-add it to the offenses_for_refetcing
                    refetching_offenses.append(offense)

                elif REFETCHING_TIME_KEY_NAME in offense:
                    # This is a rf offense and it has found events -
                    #  remove it from the offenses_for_refetching
                    refetching_offenses[:] = [rf_offense for rf_offense in refetching_offenses if
                                              rf_offense['id'] != offense_id]

                connector_scope.LOGGER.info("Found {} events. Filtering by whitelist.".format(len(events)))

                # Filter adn arrange events by rules
                events_for_rules = qradar_connector.filter_events_per_rule(events, whitelist, event_limit_per_rule)

                connector_scope.LOGGER.info(
                    "Found {0} whitelisted rules for offense with id {1}, the rules are: {2}".format(
                        len(events_for_rules), str(offense_id).encode("utf-8"),
                        str(list(events_for_rules.keys())).encode("utf-8")))

            except Exception as err:
                connector_scope.LOGGER.error('Error fetching events for offense with id: {0}, ERROR: {1}'.format(
                    str(offense_id).encode("utf-8"),
                    str(err)))
                connector_scope.LOGGER.exception(err)

                if test_handler:
                    raise

                # Add empty case with offense id and no events
                connector_scope.LOGGER.info("Creating empty case with offense id and no events or data")
                empty_events_list = [{}]
                case = qradar_connector.create_case_package(offense['id'], "Cannot fetch events for offense",
                                                            empty_events_list, environment=offense_tenant)
                cases.append(case)
                # Move on to the next offense
                continue

            # Create case package.
            for rule_name, events_for_rule in events_for_rules.items():
                connector_scope.LOGGER.info(
                    'Running on rule "{0}" from offense: {1}'.format(str(rule_name).encode("utf-8"),
                                                                     str(offense_id).encode("utf-8")))
                if events_for_rule:
                    try:
                        case = qradar_connector.create_case_package(offense['id'], rule_name, events_for_rule,
                                                                    environment=offense_tenant)

                        is_overflow = False

                        try:
                            is_overflow = connector_scope.is_overflowed_alert(
                                environment=case.environment,
                                alert_identifier=str(case.ticket_id),
                                alert_name=str(case.rule_generator),
                                product=str(case.device_product)
                            )

                        except Exception as e:
                            connector_scope.LOGGER.error(
                                "Failed to detect overflow for Alert {}".format(
                                    case.name)
                            )
                            connector_scope.LOGGER.exception(e)

                        if not is_overflow:
                            cases.append(case)
                            connector_scope.LOGGER.info(
                                'Created case package for rule "{0}" with offense id {1} with display id:{2}'.format(
                                    str(rule_name).encode("utf-8"),
                                    str(offense_id).encode("utf-8"),
                                    case.display_id
                                ))

                        else:
                            connector_scope.LOGGER.warn(
                                "{alertname}-{alertid}-{environ}-{product} found as overflow alert, skipping this alert.".format(
                                    alertname=case.name,
                                    alertid=case.ticket_id,
                                    environ=case.environment,
                                    product=case.device_product
                                )
                            )

                    except Exception as err:
                        connector_scope.LOGGER.error(
                            'Error creating case package for rule "{0}" with offense id: {1} , ERROR: {2}'.format(
                                str(rule_name).encode("utf-8"),
                                str(offense_id).encode("utf-8"),
                                str(err)
                            ))
                        connector_scope.LOGGER.exception(err)

                        if test_handler:
                            raise

                else:
                    connector_scope.LOGGER.info(
                        'No events found for rule: "{0}"'.format(str(rule_name).encode("utf-8")))

        if test_handler:
            connector_scope.LOGGER.info(" ------------ Finish Qradar Connector Test ------------ ")
        else:
            # Update last run time
            # Make the offenses_for_refetcing unique by offense id
            offenses_for_refetcing = list({offense["id"]: offense for offense in refetching_offenses}.values())
            events_count = {str(offense["id"]): int(offense.get('event_count', 0)) for offense in offenses}
            total_events_count = qradar_connector.load_events_count_from_file(events_count_file_path)
            total_events_count.update(events_count)
            qradar_connector.write_events_count_to_file(events_count_file_path,
                                                        total_events_count)
            qradar_connector.update_refetching_offenses(offenses_for_refetcing)
            connector_scope.save_timestamp(new_timestamp=new_timestamp)
            connector_scope.LOGGER.info(" ------------ Connector Finished Iteration ------------ ")

        connector_scope.return_package(cases, output_variables, log_items)

    except Exception as err:
        connector_scope.LOGGER.error('Got exception on main handler. Error: {0}'.format(err))
        connector_scope.LOGGER.exception(err)
        if test_handler:
            raise


@output_handler
def test():
    """
    Test execution - QRadar Correlations Events Connector
    """
    main_handler(test_handler=True)


@output_handler
def main():
    """
    Main execution - QRadar Correlations Events Connector
    """
    main_handler()


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == 'True':
        print("Main execution started")
        main()
    else:
        print("Test execution started")
        test()
