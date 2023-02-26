"""The main pyruckus API class."""
from .const import (
    CONF_MESHLIST_GETCONF,
    CMDSTAT_SYSTEM_GETSTAT_PREFIX,
    CMDSTAT_SYSTEM_GETSTAT_POSTFIX,
    CMDSTAT_CLIENTLIST_GETSTAT,
    CMDSTAT_APLIST_GETSTAT,
    CMDSTAT_WLANLIST_GETSTAT,
)
from .const import SystemStat as SystemStat
from .RuckusAjax import RuckusAjax
from warnings import warn

class Ruckus:
    """Class for communicating with the device."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.session = None

    def __del__(self) -> None:
        """Disconnect on delete."""
        self.disconnect()

    @staticmethod
    async def create(host: str, username: str, password: str) -> "Ruckus":
        """Create a new Ruckus object and connect."""
        ruckus = Ruckus(host, username, password)
        await ruckus.connect()
        return ruckus

    async def connect(self) -> None:
        """Create connection and login."""
        session = RuckusAjax(self.host, username=self.username, password=self.password)
        await session.login()
        self.session = session

    def disconnect(self) -> None:
        """Close the session."""
        if self.session:
            self.session.close()

    async def get_mesh_info(self) -> dict:
        meshinfo = await self.session.conf(CONF_MESHLIST_GETCONF)
        return meshinfo["mesh-list"]["mesh"]

    async def get_system_info(self, *sections: SystemStat) -> dict:
        section = ''.join(s.value for s in sections) if sections else SystemStat.DEFAULT.value
        sysinfo = await self.session.cmd_stat(CMDSTAT_SYSTEM_GETSTAT_PREFIX + section + CMDSTAT_SYSTEM_GETSTAT_POSTFIX)
        return sysinfo["response"] if  "response" in sysinfo else sysinfo["system"]

    async def get_active_client_info(self) -> dict:
        return await self.session.cmd_stat(CMDSTAT_CLIENTLIST_GETSTAT, "client")

    async def get_ap_info(self) -> dict:
        return await self.session.cmd_stat(CMDSTAT_APLIST_GETSTAT, "ap")

    async def get_wlan_info(self) -> dict:
        return await self.session.cmd_stat(CMDSTAT_WLANLIST_GETSTAT, "vap")

    async def system_info(self) -> dict:
        warn("Use  get_system_info()", DeprecationWarning)
        sysinfo = await self.get_system_info(SystemStat.SYSINFO, SystemStat.IDENTITY)
        return { "system_overview": { "name": sysinfo["identity"]["name"], "version": sysinfo["sysinfo"]["version"], "serial_number": sysinfo["sysinfo"]["serial"] } }

    async def mesh_info(self) -> dict:
        warn("Use get_mesh_info() or et_system_info(SystemStat.MESH_POLICY)", DeprecationWarning)
        meshinfo = await self.get_mesh_info()
        meshpolicy = await self.get_system_info(SystemStat.MESH_POLICY)
        return { "mesh_settings": { "mesh_status": "Enabled" if meshpolicy["mesh-policy"]["enabled"] == "true" else "Disabled", "mesh_name_essid": meshinfo["name"], "zero_touch_mesh_pre_approved_serial_number_list": { "serial_number": "unsupported" } } }

    async def mesh_name(self) -> str:
        warn("Use get_mesh_info()['name']", DeprecationWarning)
        mesh_info = await self.get_mesh_info()
        return mesh_info["name"] if "name" in mesh_info else "Ruckus Mesh"

    async def current_active_clients(self) -> dict:
        warn("Use get_active_client_info()", DeprecationWarning)
        clientstats = await self.get_active_client_info()
        return { "current_active_clients": { "clients": [{ "mac_address": c["mac"], "host_name": c["hostname"], "user_ip": c["ip"], "access_point": c["vap-mac"] } for c in clientstats ]  } }

    async def ap_info(self) -> dict:
        warn("Use get_ap_info()", DeprecationWarning)
        apstats = await self.get_ap_info()
        return { "ap": { "id": { a["id"]: { "mac_address": a["mac"], "device_name": a["devname"], "model": a["model"], "network_setting": { "gateway": a["gateway"] }} for a in apstats }}}
