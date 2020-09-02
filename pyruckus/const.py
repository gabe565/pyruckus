"""Constants used in pyruckus."""
import re

# Error strings
CONNECT_ERROR_EOF = "Could not establish connection to host"
CONNECT_ERROR_TIMEOUT = "Timed out while waiting for client"
LOGIN_ERROR_LOGIN_INCORRECT = "Login incorrect"

# Regex
CLIENTS_REGEX = re.compile(
    r"Mac Address= (?P<mac>([0-9a-f]{2}[:-]){5}([0-9a-f]{2})).+"
    r"Host Name= (?P<name>([^\s]+)?).+"
    r"IP= (?P<ip>([0-9]{1,3}[\.]){3}[0-9]{1,3})",
    re.DOTALL,
)
MESH_NAME_REGEX = re.compile(r"Mesh Name\(ESSID\)= (?P<name>([^\r]+)?)")
