"""The main pyruckus API class."""
from .const import (
    CMD_SYSTEM_INFO,
    CMD_CURRENT_ACTIVE_CLIENTS,
    CMD_AP_INFO,
    CMD_CONFIG,
    HEADER_LAST_EVENTS,
    CMD_MESH_INFO,
    MESH_SETTINGS,
    MESH_NAME_ESSID,
    CMD_WLAN,
)
from .response_parser import parse_ruckus_key_value
from .RuckusSSH import RuckusSSH


class Ruckus:
    """Class for communicating with the device."""

    def __init__(
        self, host: str, username: str, password: str, login_timeout=15, timeout=10
    ) -> None:
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
    async def create(
        host: str, username: str, password: str, login_timeout=15, timeout=10
    ) -> "Ruckus":
        """Create a new Ruckus object and connect."""
        ruckus = Ruckus(
            host, username, password, login_timeout=login_timeout, timeout=timeout
        )
        await ruckus.connect()
        return ruckus

    async def connect(self) -> bool:
        """Create SSH connection and login."""
        ssh = RuckusSSH()
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

    async def ensure_connected(self) -> bool:
        """Make sure we are connected to SSH. Reconnects if disconnected."""
        if self.ssh and self.ssh.isalive():
            return True
        else:
            return await self.connect()

    async def run_and_parse(self, cmd: str, partition=None) -> dict:
        """Run a command and parse the response."""
        await self.ensure_connected()
        result = await self.ssh.run_privileged(cmd)
        if partition:
            result = result.partition(partition)[0]
        return parse_ruckus_key_value(result)

    async def mesh_info(self) -> dict:
        """Pull the current mesh name."""
        return await self.run_and_parse(CMD_MESH_INFO)

    async def mesh_name(self) -> str:
        """Pull the current mesh name."""
        try:
            mesh_info = await self.mesh_info()
            return mesh_info[MESH_SETTINGS][MESH_NAME_ESSID]
        except KeyError:
            return "Ruckus Mesh"

    async def system_info(self) -> dict:
        """Pull the system info."""
        return await self.run_and_parse(CMD_SYSTEM_INFO)

    async def current_active_clients(self) -> dict:
        """Pull active clients from the device."""
        return await self.run_and_parse(
            CMD_CURRENT_ACTIVE_CLIENTS, partition=HEADER_LAST_EVENTS
        )

    async def ap_info(self) -> dict:
        """Pull info about current access points."""
        return await self.run_and_parse(CMD_AP_INFO)

    async def config(self) -> dict:
        """Pull all config info. WARNING: this one is slow."""
        return await self.run_and_parse(CMD_CONFIG)

    async def wlan_info(self) -> dict:
        """Pull WLAN info."""
        return await self.run_and_parse(CMD_WLAN)
