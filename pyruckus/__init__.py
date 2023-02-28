"""The main pyruckus API class."""
from .const import SystemStat as SystemStat
from .RuckusAjax import RuckusAjax
from warnings import warn
from typing import List

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
        meshinfo = await self.session.conf("<ajax-request action='getconf' comp='mesh-list' DECRYPT_X='true'/>")
        return meshinfo["mesh-list"]["mesh"]

    async def get_blocked_info(self) -> List:
        blockedinfo = await self.session.conf("<ajax-request action='getconf' comp='acl-list' updater='page.0.5' />", ["accept", "deny", "acl"])
        denylist = blockedinfo[0]["deny"] if "deny" in blockedinfo[0] else None
        return [] if not denylist else denylist

    async def get_system_info(self, *sections: SystemStat) -> dict:
        section = ''.join(s.value for s in sections) if sections else SystemStat.DEFAULT.value
        sysinfo = await self.session.cmd_stat(f"<ajax-request action='getstat' comp='system'>{section}</ajax-request>")
        return sysinfo["response"] if  "response" in sysinfo else sysinfo["system"]

    async def get_active_client_info(self) -> List:
        return await self.session.cmd_stat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><client LEVEL='1' /></ajax-request>", ["client"])

    async def get_ap_info(self) -> List:
        return await self.session.cmd_stat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><ap LEVEL='1' /></ajax-request>", ["ap"])

    async def get_wlan_info(self) -> List:
        return await self.session.cmd_stat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'><vap INTERVAL-STATS='no' LEVEL='1' /></ajax-request>", ["vap"])

    async def do_block_client(self, mac: str) -> None:
        await self.session.cmd_stat(f"<ajax-request action='docmd' xcmd='block' checkAbility='10' comp='stamgr'><xcmd check-ability='10' tag='client' acl-id='1' client='{mac}' cmd='block'/></ajax-request>")

    async def do_unblock_client(self, mac: str) -> None:
        blocked = await self.get_blocked_info()
        remaining = ''.join((f"<deny mac='{deny['mac']}' type='single'/>" for deny in filter(lambda b: (b["mac"] != mac), blocked)))
        await self.session.conf(f"<ajax-request action='updobj' comp='acl-list' updater='blocked-clients'><acl id='1' name='System' description='System' default-mode='allow' EDITABLE='false'>{remaining}</acl></ajax-request>")

    async def system_info(self) -> dict:
        warn("Use  get_system_info()", DeprecationWarning)
        sysinfo = await self.get_system_info(SystemStat.SYSINFO, SystemStat.IDENTITY)
        return { "system_overview": { "name": sysinfo["identity"]["name"], "version": sysinfo["sysinfo"]["version"], "serial_number": sysinfo["sysinfo"]["serial"] } }

    async def mesh_info(self) -> dict:
        warn("Use get_mesh_info() or get_system_info(SystemStat.MESH_POLICY)", DeprecationWarning)
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
