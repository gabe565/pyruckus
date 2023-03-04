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
        return [] if not denylist else [d for d in denylist if d]

    async def get_system_info(self, *sections: SystemStat) -> dict:
        section = ''.join(s.value for s in sections) if sections else SystemStat.DEFAULT.value
        sysinfo = await self.session.cmd_stat(f"<ajax-request action='getstat' comp='system'>{section}</ajax-request>")
        return sysinfo["response"] if "response" in sysinfo else sysinfo["system"]

    async def get_active_client_info(self) -> List:
        return await self.session.cmd_stat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><client LEVEL='1' /></ajax-request>", ["client"])

    async def get_inactive_client_info(self) -> List:
        return await self.session.cmd_stat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><clientlist period='0' /></ajax-request>", ["client"])

    async def get_ap_info(self) -> List:
        return await self.session.cmd_stat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><ap LEVEL='1' /></ajax-request>", ["ap"])

    async def get_ap_group_info(self) -> List:
        return await self.session.cmd_stat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><apgroup /></ajax-request>", ["group", "radio", "ap"])

    async def get_vap_info(self) -> List:
        return await self.session.cmd_stat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'><vap INTERVAL-STATS='no' LEVEL='1' /></ajax-request>", ["vap"])

    async def get_wlan_info(self) -> List:
        return await self.session.conf("<ajax-request action='getconf' DECRYPT_X='true' updater='wlansvc-list.0.5' comp='wlansvc-list'/>", ["wlansvc"])

    async def get_wlan_group_info(self) -> List:
        return await self.session.cmd_stat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'><wlangroup /></ajax-request>", ["wlangroup", "wlan"])

    async def do_block_client(self, mac: str) -> None:
        await self.session.cmd_stat(f"<ajax-request action='docmd' xcmd='block' checkAbility='10' comp='stamgr'><xcmd check-ability='10' tag='client' acl-id='1' client='{mac}' cmd='block'><client client='{mac}' acl-id='1' hostname=''></client></xcmd></ajax-request>")

    async def do_unblock_client(self, mac: str) -> None:
        blocked = await self.get_blocked_info()
        remaining = ''.join((f"<deny mac='{deny['mac']}' type='single'/>" for deny in blocked if deny["mac"] != mac))
        await self.session.conf(f"<ajax-request action='updobj' comp='acl-list' updater='blocked-clients'><acl id='1' name='System' description='System' default-mode='allow' EDITABLE='false'>{remaining}</acl></ajax-request>")

    async def do_disable_wlan(self, ssid: str, disable_wlan: bool = True) -> None:
        wlanid = await self.__find_wlan_by_ssid(ssid)
        if wlanid:
            await self.session.conf(f"<ajax-request action='updobj' updater='wlansvc-list.0.5' comp='wlansvc-list'><wlansvc id='{wlanid}' enable-type='{1 if disable_wlan else 0}' IS_PARTIAL='true'/></ajax-request>")

    async def do_enable_wlan(self, ssid: str) -> None:
        await self.do_disable_wlan(ssid, False)

    async def do_hide_ap_leds(self, mac: str, leds_off: bool = True) -> None:
        apid = await self.__find_ap_by_mac(mac)
        if apid:
            await self.session.conf(f"<ajax-request action='updobj' updater='ap-list.0.5' comp='ap-list'><ap id='{apid}' IS_PARTIAL='true' led-off='{str(leds_off).lower()}' /></ajax-request>")

    async def do_show_ap_leds(self, mac: str) -> None:
        await self.do_hide_ap_leds(mac, False)

    async def __find_ap_by_mac(self, mac:str) -> str:
        return next((ap["id"] for ap in await self.get_ap_info() if ap["mac"] == mac), None)

    async def __find_wlan_by_ssid(self, ssid:str) -> str:
        return next((wlan["id"] for wlan in await self.get_wlan_info() if wlan["ssid"] == ssid), None)

    async def system_info(self) -> dict:
        warn("Use get_system_info()", DeprecationWarning)
        sysinfo = await self.get_system_info(SystemStat.SYSINFO, SystemStat.IDENTITY)
        return {"system_overview": {"name": sysinfo["identity"]["name"], "version": sysinfo["sysinfo"]["version"], "serial_number": sysinfo["sysinfo"]["serial"]}}

    async def mesh_info(self) -> dict:
        warn("Use get_mesh_info() or get_system_info(SystemStat.MESH_POLICY)", DeprecationWarning)
        meshinfo = await self.get_mesh_info()
        meshpolicy = await self.get_system_info(SystemStat.MESH_POLICY)
        return {"mesh_settings": {"mesh_status": "Enabled" if meshpolicy["mesh-policy"]["enabled"] == "true" else "Disabled", "mesh_name_essid": meshinfo["name"], "zero_touch_mesh_pre_approved_serial_number_list": {"serial_number": "unsupported"}}}

    async def mesh_name(self) -> str:
        warn("Use get_mesh_info()['name']", DeprecationWarning)
        mesh_info = await self.get_mesh_info()
        return mesh_info["name"] if "name" in mesh_info else "Ruckus Mesh"

    async def current_active_clients(self) -> dict:
        warn("Use get_active_client_info()", DeprecationWarning)
        clientstats = await self.get_active_client_info()
        return {"current_active_clients": {"clients": [{"mac_address": c["mac"], "host_name": c["hostname"], "user_ip": c["ip"], "access_point": c["vap-mac"]} for c in clientstats]}}

    async def ap_info(self) -> dict:
        warn("Use get_ap_info()", DeprecationWarning)
        apstats = await self.get_ap_info()
        return {"ap": {"id": {a["id"]: {"mac_address": a["mac"], "device_name": a["devname"], "model": a["model"], "network_setting": {"gateway": a["gateway"]}} for a in apstats}}}
