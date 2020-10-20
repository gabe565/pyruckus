"""Constants used in pyruckus."""

# Error strings
CONNECT_ERROR_EOF = "Could not establish connection to host"
CONNECT_ERROR_TIMEOUT = "Timed out while waiting for client"
CONNECT_ERROR_PRIVILEGED_ALREADY_LOGGED_IN = "A privileged user is already logged in"
LOGIN_ERROR_LOGIN_INCORRECT = "Login incorrect"

# Commands
CMD_ENABLE = "enable"
CMD_ENABLE_FORCE = "force"
CMD_DISABLE = "disable"
CMD_MESH_INFO = "show mesh info"
CMD_SYSTEM_INFO = "show sysinfo"
CMD_CURRENT_ACTIVE_CLIENTS = "show current-active-clients all"
CMD_AP_INFO = "show ap all"
CMD_CONFIG = "show config"
CMD_WLAN = "show wlan all"

# Other
MESH_SETTINGS = "mesh_settings"
MESH_NAME_ESSID = "mesh_name_essid"
SERIAL_NUMBER = "serial_number"
HEADER_LAST_EVENTS = "Last 300 Events/Activities:"
