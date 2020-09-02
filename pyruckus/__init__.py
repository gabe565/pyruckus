import re

from .RuckusSSH import RuckusSSH
from .const import CLIENTS_REGEX, MESH_NAME_REGEX


class Ruckus:
    """Class for communicating with the device."""

    def __init__(self, host: str, username: str, password: str, login_timeout=15, timeout=10) -> None:
        """Set runtime configuration."""
        self.host = host
        self.username = username
        self.password = password
        self.login_timeout = login_timeout
        self.timeout = timeout

        self.ssh = None
        self.connect()

    def __del__(self) -> None:
        """Disconnect on delete."""
        self.disconnect()

    def connect(self) -> None:
        """Create SSH connection and login."""
        ssh = RuckusSSH()
        ssh.login(self.host, username=self.username, password=self.password, login_timeout=self.login_timeout)
        self.ssh = ssh

    def disconnect(self) -> None:
        """Close the SSH session."""
        if self.ssh and self.ssh.isalive():
            self.ssh.close()

    def clients(self) -> dict:
        """Pull active clients from the device."""
        if not self.ssh.isalive():
            self.connect()

        self.ssh.enable()
        self.ssh.sendline("show current-active-clients all")
        self.ssh.prompt()

        result = self.ssh.before.decode("utf-8")

        devices = {}
        for client in re.split("Clients:", result):
            match = CLIENTS_REGEX.search(client)
            if match:
                devices[match.group("mac")] = {
                    "ip": match.group("ip"),
                    "mac": match.group("mac"),
                    "name": match.group("name"),
                }

        return devices

    def mesh_name(self) -> str:
        """Pull the current mesh name."""
        if not self.ssh.isalive():
            self.connect()

        self.ssh.enable()
        self.ssh.sendline("show mesh info")
        self.ssh.prompt()

        result = self.ssh.before.decode("utf-8")

        match = MESH_NAME_REGEX.search(result)

        if match:
            return match.group("name")
        else:
            return "Ruckus Mesh"
