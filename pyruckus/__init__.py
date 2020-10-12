import re

from .RuckusSSH import RuckusSSH
from .const import CLIENTS_REGEX


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
        ssh = RuckusSSH(encoding="utf-8")
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

        result = self.ssh.run_privileged("show current-active-clients all")

        devices = {}
        for client in re.split("Clients:", result):
            match = CLIENTS_REGEX.search(client)
            if match:
                devices[match.group("mac")] = {
                    "ip_address": match.group("ip"),
                    "mac": match.group("mac"),
                    "name": match.group("name"),
                }

        return devices

    def mesh_name(self) -> str:
        """Pull the current mesh name."""
        try:
            return self.mesh_info()['Mesh Settings']['Mesh Name(ESSID)']
        except KeyError:
            return 'Ruckus Mesh'

    @staticmethod
    def __parse_kv(response) -> dict:
        """Parse Ruckus nested key-value output into a dict."""
        result = {}
        indent = 0

        node = result
        parent_node = result
        for line in response.splitlines():
            if not line:
                continue

            if line.endswith(":") and "= " not in line:
                line = line.rstrip(":")
                stripped_line = line.lstrip()

                last_indent = indent
                indent = len(line) - len(stripped_line)

                new_node = {}
                if indent > last_indent:
                    parent_node = node
                elif indent < last_indent:
                    parent_node = result

                if stripped_line in parent_node:
                    if isinstance(parent_node[stripped_line], list):
                        parent_node[stripped_line].append(new_node)
                    else:
                        last_node = parent_node[stripped_line]
                        parent_node[stripped_line] = [last_node, new_node]
                else:
                    parent_node[stripped_line] = new_node

                node = new_node
            else:
                key, _, value = line.partition("= ")
                if key and value:
                    node[key.strip()] = value.strip()

        return result

    def mesh_info(self) -> dict:
        """Pull the current mesh name."""
        if not self.ssh.isalive():
            self.connect()

        result = self.ssh.run_privileged("show mesh info")

        return self.__parse_kv(result)

    def system_info(self) -> dict:
        """Pull the system info."""
        if not self.ssh.isalive():
            self.connect()

        result = self.ssh.run_privileged("show sysinfo")

        return self.__parse_kv(result)

    def current_active_clients(self) -> dict:
        """Pull the current active clients."""
        if not self.ssh.isalive():
            self.connect()

        result = self.ssh.run_privileged("show current-active-clients all")
        result, _, _ = result.partition("Last 300 Events/Activities:")

        return self.__parse_kv(result)
