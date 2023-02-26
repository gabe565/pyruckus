"""Constants used in pyruckus."""
from enum import Enum

# Error strings
CONNECT_ERROR_EOF = "Could not establish connection to host"
CONNECT_ERROR_TIMEOUT = "Timed out while waiting for client"
AJAX_POST_REDIRECTED_ERROR = "Insufficient permission to run this command"
AJAX_POST_NORESULT_ERROR = "The command was not understood"
LOGIN_ERROR_LOGIN_INCORRECT = "Login incorrect"

# ajax payloads
CMDSTAT_SYSTEM_GETSTAT_PREFIX = "<ajax-request action='getstat' comp='system'>"
CMDSTAT_SYSTEM_GETSTAT_POSTFIX = "</ajax-request>"
CONF_MESHLIST_GETCONF= "<ajax-request action='getconf' comp='mesh-list' DECRYPT_X='true'/>"
CMDSTAT_CLIENTLIST_GETSTAT= "<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><client LEVEL='1' /></ajax-request>"
CMDSTAT_APLIST_GETSTAT= "<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><ap LEVEL='1' /></ajax-request>"
CMDSTAT_WLANLIST_GETSTAT= "<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'><vap INTERVAL-STATS='yes' INTERVAL-START='1604710474' INTERVAL-STOP='1605315274' LEVEL='1' /></ajax-request>"


class SystemStat(Enum):
    ALL = ""
    DEFAULT = "<identity/><sysinfo/><port/>"
    IDENTITY = "<identity/>"
    SYSINFO = "<sysinfo/>"
    PORT = "<port/>"
    ADMIN = "<admin/>"
    MESH_POLICY = "<mesh-policy/>"
