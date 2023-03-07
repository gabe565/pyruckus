import ssl
from re import IGNORECASE, match
from typing import List, Any
from warnings import warn

import aiohttp
import xmltodict

from .const import (
    AJAX_POST_NORESULT_ERROR,
    AJAX_POST_REDIRECTED_ERROR,
    CONNECT_ERROR_TEMPORARY,
    LOGIN_ERROR_LOGIN_INCORRECT,
    VALUE_ERROR_INVALID_MAC,
)
from .const import SystemStat as SystemStat
from .exceptions import AuthenticationError


class Ruckus:

    async def get_mesh_info(self) -> dict:
        meshinfo = await self.conf("<ajax-request action='getconf' comp='mesh-list' DECRYPT_X='true'/>")
        return meshinfo["mesh-list"]["mesh"]

    async def get_zerotouch_mesh_info(self) -> dict:
        return await self.conf("<ajax-request action='getconf' updater='ztmeshSerial-list.0.5' comp='ztmeshSerial-list'/>", ["ztmeshSerial"])

    async def get_blocked_info(self) -> List:
        blockedinfo = await self.conf("<ajax-request action='getconf' comp='acl-list' updater='page.0.5' />", ["accept", "deny", "acl"])
        denylist = blockedinfo[0]["deny"] if "deny" in blockedinfo[0] else None
        return [] if not denylist else [d for d in denylist if d]

    async def get_system_info(self, *sections: SystemStat) -> dict:
        section = ''.join(s.value for s in sections) if sections else SystemStat.DEFAULT.value
        sysinfo = await self.cmd_stat(f"<ajax-request action='getstat' comp='system'>{section}</ajax-request>")
        return sysinfo["response"] if "response" in sysinfo else sysinfo["system"]

    async def get_active_client_info(self) -> List:
        return await self.cmd_stat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><client LEVEL='1' /></ajax-request>", ["client"])

    async def get_inactive_client_info(self) -> List:
        return await self.cmd_stat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><clientlist period='0' /></ajax-request>", ["client"])

    async def get_ap_info(self) -> List:
        return await self.cmd_stat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><ap LEVEL='1' /></ajax-request>", ["ap"])

    async def get_ap_group_info(self) -> List:
        return await self.cmd_stat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><apgroup /></ajax-request>", ["group", "radio", "ap"])

    async def get_vap_info(self) -> List:
        return await self.cmd_stat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'><vap INTERVAL-STATS='no' LEVEL='1' /></ajax-request>", ["vap"])

    async def get_wlan_info(self) -> List:
        return await self.conf("<ajax-request action='getconf' DECRYPT_X='true' updater='wlansvc-list.0.5' comp='wlansvc-list'/>", ["wlansvc"])

    async def get_wlan_group_info(self) -> List:
        return await self.cmd_stat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'><wlangroup /></ajax-request>", ["wlangroup", "wlan"])

    async def do_block_client(self, mac: str) -> None:
        normalized_mac = self.__normalize_mac(mac)
        await self.cmd_stat(f"<ajax-request action='docmd' xcmd='block' checkAbility='10' comp='stamgr'><xcmd check-ability='10' tag='client' acl-id='1' client='{normalized_mac}' cmd='block'><client client='{normalized_mac}' acl-id='1' hostname=''></client></xcmd></ajax-request>")

    async def do_unblock_client(self, mac: str) -> None:
        normalized_mac = self.__normalize_mac(mac)
        blocked = await self.get_blocked_info()
        remaining = ''.join((f"<deny mac='{deny['mac']}' type='single'/>" for deny in blocked if deny["mac"] != normalized_mac))
        await self.conf(f"<ajax-request action='updobj' comp='acl-list' updater='blocked-clients'><acl id='1' name='System' description='System' default-mode='allow' EDITABLE='false'>{remaining}</acl></ajax-request>")

    async def do_disable_wlan(self, ssid: str, disable_wlan: bool = True) -> None:
        wlanid = await self.__find_wlan_by_ssid(ssid)
        if wlanid:
            await self.conf(f"<ajax-request action='updobj' updater='wlansvc-list.0.5' comp='wlansvc-list'><wlansvc id='{wlanid}' enable-type='{1 if disable_wlan else 0}' IS_PARTIAL='true'/></ajax-request>")

    async def do_enable_wlan(self, ssid: str) -> None:
        await self.do_disable_wlan(ssid, False)

    async def do_hide_ap_leds(self, mac: str, leds_off: bool = True) -> None:
        normalized_mac = self.__normalize_mac(mac)
        apid = await self.__find_ap_by_mac(normalized_mac)
        if apid:
            await self.conf(f"<ajax-request action='updobj' updater='ap-list.0.5' comp='ap-list'><ap id='{apid}' IS_PARTIAL='true' led-off='{str(leds_off).lower()}' /></ajax-request>")

    async def do_show_ap_leds(self, mac: str) -> None:
        await self.do_hide_ap_leds(mac, False)

    async def __find_ap_by_mac(self, mac: str) -> str:
        return next((ap["id"] for ap in await self.get_ap_info() if ap["mac"] == mac), None)

    async def __find_wlan_by_ssid(self, ssid: str) -> str:
        return next((wlan["id"] for wlan in await self.get_wlan_info() if wlan["ssid"] == ssid), None)

    async def system_info(self) -> dict:
        warn("Use get_system_info()", DeprecationWarning)
        sysinfo = await self.get_system_info(SystemStat.SYSINFO, SystemStat.IDENTITY)
        return {"system_overview": {"name": sysinfo["identity"]["name"], "version": sysinfo["sysinfo"]["version"], "serial_number": sysinfo["sysinfo"]["serial"]}}

    async def mesh_info(self) -> dict:
        warn("Use get_mesh_info() or get_system_info(SystemStat.MESH_POLICY)", DeprecationWarning)
        meshinfo = await self.get_mesh_info()
        meshpolicy = await self.get_system_info(SystemStat.MESH_POLICY)
        return {"mesh_settings": {"mesh_status": "Enabled" if meshpolicy["mesh-policy"]["enabled"] == "true" else "Disabled", "mesh_name_essid": meshinfo["name"]}, "zero_touch_mesh_pre_approved_serial_number_list": {"serial_number": "unsupported"}}

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

    async def cmd_stat(self, data: str, collection_elements: List[str] = None) -> dict | List:
        return await self.__ajax_post(self.__cmdstat_url, data, collection_elements)

    async def conf(self, data: str, collection_elements: List[str] = None) -> dict | List:
        return await self.__ajax_post(self.__conf_url, data, collection_elements)

    async def login(self) -> None:

        # create aiohttp session if we don't have one
        if not self.session:
            self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), cookie_jar=aiohttp.CookieJar(unsafe=True))

        # locate the admin pages: /admin/* for Unleashed and ZD 9.x, /admin10/* for ZD 10.x
        async with self.session.head(f"https://{self.host}", timeout=3, ssl=self.ssl_context, allow_redirects=False) as h:
            self.__login_url = h.headers["Location"]
            self.__base_url = self.__login_url.rsplit('/', 1)[0]
            self.__cmdstat_url = self.__base_url + "/_cmdstat.jsp"
            self.__conf_url = self.__base_url + "/_conf.jsp"

        # login and collect CSRF token
        async with self.session.head(self.__login_url, params={"username": self.username, "password": self.password, "ok": "Log In"}, timeout=3, ssl=self.ssl_context, allow_redirects=False) as h:
            if h.status == 200:  # if username/password were valid we'd be redirected to the main admin page
                raise AuthenticationError(LOGIN_ERROR_LOGIN_INCORRECT)
            if "HTTP_X_CSRF_TOKEN" in h.headers:  # modern ZD and Unleashed return CSRF token in header
                self.session.headers["X-CSRF-Token"] = h.headers["HTTP_X_CSRF_TOKEN"]
            else:  # older ZD and Unleashed require you to scrape the CSRF token from a page's javascript
                async with self.session.get(self.__base_url + "/_csrfTokenVar.jsp", timeout=3, ssl=self.ssl_context, allow_redirects=False) as r:
                    if r.status == 200:
                        csrf_token = xmltodict.parse(await r.text())["script"].split('=').pop()[2:12]
                        self.session.headers["X-CSRF-Token"] = csrf_token
                    elif r.status == 500:  # even older ZD don't use CSRF tokens at all
                        pass
                    else:  # token page is a redirect, maybe temporary Unleashed Rebuilding placeholder page is showing
                        raise ConnectionRefusedError(CONNECT_ERROR_TEMPORARY)

    async def logout(self) -> None:
        if self.session:
            async with self.session.head(self.__login_url, params={"logout": "1"}, timeout=3, ssl=self.ssl_context, allow_redirects=False):
                await self.session.close()

    def __process_ruckus_ajax_xml(self, path, key, value):
        if key.startswith("x-") and value:  # passphrases are obfuscated and stored with an x- prefix; decrypt these
            return key[2:], ''.join(chr(ord(letter) - 1) for letter in value)
        elif key == "apstamgr-stat" and not value:  # return an empty array rather than None, for ease of use
            return key, []
        elif key == "status" and value and value.isnumeric() and path and len(path) > 0 and path[-1][0] == "client":  # client status is numeric code for active, and name for inactive. Show name for everything
            description = "Authorized" if value == "1" else "Authenticating" if value == "2" else "PSK Expired" if value == "3" else "Authorized(Deny)" if value == "4" else "Authorized(Permit)" if value == "5" else "Unauthorized"
            return key, description
        else:
            return key, value

    async def __ajax_post(self, cmd: str, data: str, collection_elements: List[str] = None, retrying: bool = False) -> dict | List:

        # request data
        async with self.session.post(cmd, data=data, headers={"Content-Type": "text/xml"}, ssl=self.ssl_context, allow_redirects=False) as r:

            if r.status == 302:  # if the session is dead then we're redirected to the login page
                if retrying:  # we tried logging in again, but the redirect still happens - maybe password changed?
                    raise PermissionError(AJAX_POST_REDIRECTED_ERROR)
                await self.login()  # try logging in again, then retry post
                return await self.__ajax_post(cmd, data, collection_elements, retrying=True)

            result_text = await r.text()
            if not result_text or result_text == "\n":  # if the ajax request payload wasn't understood then we get an empty page back
                raise RuntimeError(AJAX_POST_NORESULT_ERROR)

            # convert xml and unwrap collection
            force_list = None if not collection_elements else {ce: True for ce in collection_elements}
            result = xmltodict.parse(result_text, encoding="utf-8", attr_prefix='', postprocessor=self.__process_ruckus_ajax_xml, force_list=force_list)
            collection_list = [] if not collection_elements else [f"{ce}-list" for ce in collection_elements] + collection_elements
            for key in ["ajax-response", "response", "apstamgr-stat"] + collection_list:
                if result and key and key in result:
                    result = result[key]
            return result or []

    def __normalize_mac(self, mac: str) -> str:
        if mac and match(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", string=mac, flags=IGNORECASE):
            return mac.replace('-', ':').lower()
        raise ValueError(VALUE_ERROR_INVALID_MAC)

    def __init__(self, host: str, username: str, password: str) -> None:
        self.host = host
        self.username = username
        self.password = password

        self.__login_url = None
        self.__base_url = None
        self.__cmdstat_url = None
        self.__conf_url = None
        self.session = None

        # create ssl context so we ignore cert errors
        context = ssl.create_default_context()
        context.set_ciphers("DEFAULT")
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.ssl_context = context

    async def __aenter__(self) -> "Ruckus":
        await self.login()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.logout()
