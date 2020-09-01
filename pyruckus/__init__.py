import re

from .RuckusSSH import RuckusSSH
from .const import CLIENTS_REGEX


class Ruckus:
    """Class for communicating with the device."""

    def __init__(self, server: str, username: str, password: str, login_timeout=15, timeout=10):
        """Set runtime configuration."""
        self.server = server
        self.username = username
        self.password = password
        self.login_timeout = login_timeout
        self.timeout = timeout

        self.ssh = None
        self.connect()

    def __del__(self):
        """Disconnect on delete."""
        self.disconnect()

    def connect(self):
        """Create SSH connection and login."""
        ssh = RuckusSSH()
        ssh.login(self.server, username=self.username, password=self.password, login_timeout=self.login_timeout)
        self.ssh = ssh

    def disconnect(self):
        """Close the SSH session."""
        self.ssh.close()

    def clients(self):
        """Pull active clients from the device."""
        if not self.ssh.isalive():
            self.connect()

        self.ssh.enable()
        self.ssh.sendline("show current-active-clients all")
        self.ssh.prompt()

        devices_result = self.ssh.before

        devices = {}
        for client in re.split("Clients:", devices_result.decode("utf-8")):
            match = CLIENTS_REGEX.search(client)
            if match:
                devices[match.group("ip")] = {
                    "ip": match.group("ip"),
                    "mac": match.group("mac"),
                    "name": match.group("name"),
                }

        return devices
