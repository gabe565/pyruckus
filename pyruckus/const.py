"""Constants used in pyruckus."""
from enum import Enum

# Error strings
CONNECT_ERROR_EOF = "Could not establish connection to host"
CONNECT_ERROR_TIMEOUT = "Timed out while waiting for client"
CONNECT_ERROR_TEMPORARY = "Temporarily unable to handle the request"
AJAX_POST_REDIRECTED_ERROR = "Insufficient permission to run this command"
AJAX_POST_NORESULT_ERROR = "The command was not understood"
LOGIN_ERROR_LOGIN_INCORRECT = "Login incorrect"
VALUE_ERROR_INVALID_MAC = "Invalid MAC"


class SystemStat(Enum):
    ALL = ""
    DEFAULT = "<identity/><sysinfo/><port/>"
    IDENTITY = "<identity/>"
    SYSINFO = "<sysinfo/>"
    PORT = "<port/>"
    ADMIN = "<admin/>"
    MESH_POLICY = "<mesh-policy/>"
