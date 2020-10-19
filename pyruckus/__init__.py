"""The main pyruckus API class."""
from slugify import slugify

from .const import CMD_SYSTEM_INFO, CMD_CURRENT_ACTIVE_CLIENTS, CMD_AP_INFO, HEADER_300_EVENTS, \
    CMD_MESH_INFO, MESH_SETTINGS, MESH_NAME_ESSID
from .RuckusSSH import RuckusSSH


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

    def __del__(self) -> None:
        """Disconnect on delete."""
        self.disconnect()

    @staticmethod
    async def create(host: str, username: str, password: str, login_timeout=15, timeout=10) -> "Ruckus":
        """Create a new Ruckus object and connect."""
        ruckus = Ruckus(host, username, password, login_timeout=login_timeout, timeout=timeout)
        await ruckus.connect()
        return ruckus

    async def connect(self) -> bool:
        """Create SSH connection and login."""
        ssh = RuckusSSH(encoding="utf-8")
        result = await ssh.login(
            self.host,
            username=self.username,
            password=self.password,
            login_timeout=self.login_timeout,
        )
        self.ssh = ssh
        return result

    def disconnect(self) -> None:
        """Close the SSH session."""
        if self.ssh and self.ssh.isalive():
            self.ssh.close()

    @staticmethod
    def __parse_kv(response) -> dict:
        """Parse Ruckus nested key-value output into a dict."""
        root = {}
        indent = 0

        node = root
        breadcrumbs = [root]
        for line in response.splitlines():
            # Skip empty lines
            if not line.strip():
                continue

            # Line is a "header" instead of a key-value pair
            is_header = line.endswith(":") and "= " not in line

            prev_indent = indent
            indent = len(line) - len(line.lstrip())

            # If the indent has decreased, remove nodes from the breadcrumbs
            if indent < prev_indent:
                difference = int((indent - prev_indent) / 2)
                breadcrumbs = breadcrumbs[:difference]
                node = breadcrumbs[-1]

            if is_header:
                # Remove colon, then strip whitespace
                line = slugify(line[:-1], separator="_")
                parent_node = breadcrumbs[-1]
                node = {}

                # If current header already exists, convert to list
                if line in parent_node:
                    if isinstance(parent_node[line], list):
                        parent_node[line].append(node)
                    else:
                        prev_node = parent_node[line]
                        parent_node[line] = [prev_node, node]
                else:
                    parent_node[line] = node

                breadcrumbs.append(node)
            else:
                key, _, value = line.partition("=")
                key = slugify(key, separator="_")
                value = value.strip()
                if key:
                    node[key] = value

        return root

    async def ensure_connected(self) -> bool:
        """Make sure we are connected to SSH. Reconnects if disconnected."""
        if self.ssh and self.ssh.isalive():
            return True
        else:
            return await self.connect()

    async def mesh_info(self) -> dict:
        """Pull the current mesh name."""
        await self.ensure_connected()
        result = await self.ssh.run_privileged(CMD_MESH_INFO)
        return self.__parse_kv(result)

    async def mesh_name(self) -> str:
        """Pull the current mesh name."""
        try:
            mesh_info = await self.mesh_info()
            return mesh_info[MESH_SETTINGS][MESH_NAME_ESSID]
        except KeyError:
            return 'Ruckus Mesh'

    async def system_info(self) -> dict:
        """Pull the system info."""
        await self.ensure_connected()
        result = await self.ssh.run_privileged(CMD_SYSTEM_INFO)
        return self.__parse_kv(result)

    async def current_active_clients(self) -> dict:
        """Pull active clients from the device."""
        await self.ensure_connected()
        result = await self.ssh.run_privileged(CMD_CURRENT_ACTIVE_CLIENTS)
        result, _, _ = result.partition(HEADER_300_EVENTS)
        return self.__parse_kv(result)

    async def ap_info(self) -> dict:
        """Pull info about current access points."""
        await self.ensure_connected()
        result = await self.ssh.run_privileged(CMD_AP_INFO)
        return self.__parse_kv(result)
