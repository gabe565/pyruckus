import ssl
from re import IGNORECASE, match
from typing import List, Any
from warnings import warn
import xml.etree.ElementTree as ET
import xml.sax.saxutils as saxutils

import aiohttp
import xmltodict

from .const import (
    AJAX_POST_NORESULT_ERROR,
    AJAX_POST_REDIRECTED_ERROR,
    CONNECT_ERROR_TEMPORARY,
    LOGIN_ERROR_LOGIN_INCORRECT,
    VALUE_ERROR_INVALID_MAC,
    VALUE_ERROR_INVALID_PASSPHRASE_LEN,
    VALUE_ERROR_INVALID_PASSPHRASE_JS
)
from .const import SystemStat as SystemStat
from .exceptions import AuthenticationError


class Ruckus:
    # Copyright (C) 2023 by Patternicity bsd0@patterni.city
    # Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.
    # THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

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
        sysinfo = await self.cmdstat(f"<ajax-request action='getstat' comp='system'>{section}</ajax-request>")
        return sysinfo["response"] if "response" in sysinfo else sysinfo["system"]

    async def get_active_client_info(self) -> List:
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><client LEVEL='1' /></ajax-request>", ["client"])

    async def get_inactive_client_info(self) -> List:
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><clientlist period='0' /></ajax-request>", ["client"])

    async def get_ap_info(self) -> List:
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><ap LEVEL='1' /></ajax-request>", ["ap"])

    async def get_ap_group_info(self) -> List:
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><apgroup /></ajax-request>", ["group", "radio", "ap"])

    async def get_vap_info(self) -> List:
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'><vap INTERVAL-STATS='no' LEVEL='1' /></ajax-request>", ["vap"])

    async def get_wlan_info(self) -> List:
        return await self.conf("<ajax-request action='getconf' DECRYPT_X='true' updater='wlansvc-list.0.5' comp='wlansvc-list'/>", ["wlansvc"])

    async def get_wlan_group_info(self) -> List:
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'><wlangroup /></ajax-request>", ["wlangroup", "wlan"])

    async def do_block_client(self, mac: str) -> None:
        mac = self._normalize_mac(mac)
        await self.cmdstat(f"<ajax-request action='docmd' xcmd='block' checkAbility='10' comp='stamgr'><xcmd check-ability='10' tag='client' acl-id='1' client='{mac}' cmd='block'><client client='{mac}' acl-id='1' hostname=''></client></xcmd></ajax-request>")

    async def do_unblock_client(self, mac: str) -> None:
        mac = self._normalize_mac(mac)
        blocked = await self.get_blocked_info()
        remaining = ''.join((f"<deny mac='{deny['mac']}' type='single'/>" for deny in blocked if deny["mac"] != mac))
        await self._conf_noparse(f"<ajax-request action='updobj' comp='acl-list' updater='blocked-clients'><acl id='1' name='System' description='System' default-mode='allow' EDITABLE='false'>{remaining}</acl></ajax-request>")

    async def do_disable_wlan(self, ssid: str, disable_wlan: bool = True) -> None:
        wlan = await self._find_wlan_by_ssid(ssid)
        if wlan:
            await self._conf_noparse(f"<ajax-request action='updobj' updater='wlansvc-list.0.5' comp='wlansvc-list'><wlansvc id='{wlan['id']}' enable-type='{1 if disable_wlan else 0}' IS_PARTIAL='true'/></ajax-request>")

    async def do_enable_wlan(self, ssid: str) -> None:
        await self.do_disable_wlan(ssid, False)

    async def do_set_wlan_password(self, ssid: str, password: str, sae_password: str = None) -> None:
        # IS_PARTIAL prepopulates all subelements, so that any wpa element we provide would result in 2 wpa elements.
        # So we have to do what the web UI does: grab the wlan definition, make our changes, then post the entire thing back.
        password = self._validate_passphrase(password)
        sae_password = self._validate_passphrase(sae_password or password)
        xml = await self._conf_noparse("<ajax-request action='getconf' DECRYPT_X='true' updater='wlansvc-list.0.5' comp='wlansvc-list'/>")
        root = ET.fromstring(xml)
        wlansvc = root.find(".//wlansvc[@ssid='%s']" % saxutils.escape(ssid))
        if wlansvc:
            wpa = wlansvc.find("wpa")
            if wpa.get("passphrase") is not None:
                wpa.set("passphrase", password)
                wpa.set("x-passphrase", password)
            if wpa.get("sae-passphrase") is not None:
                wpa.set("sae-passphrase", password)
                wpa.set("x-sae-passphrase", password)
            xml_bytes = ET.tostring(wlansvc)
            await self.conf(f"<ajax-request action='updobj' updater='wlan' comp='wlansvc-list'>{xml_bytes.decode('utf-8')}</ajax-request>")

    async def do_hide_ap_leds(self, mac: str, leds_off: bool = True) -> None:
        mac = self._normalize_mac(mac)
        ap = await self._find_ap_by_mac(mac)
        if ap:
            await self._conf_noparse(f"<ajax-request action='updobj' updater='ap-list.0.5' comp='ap-list'><ap id='{ap['id']}' IS_PARTIAL='true' led-off='{str(leds_off).lower()}' /></ajax-request>")

    async def do_show_ap_leds(self, mac: str) -> None:
        await self.do_hide_ap_leds(mac, False)

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

    async def _find_ap_by_mac(self, mac: str) -> dict:
        return next((ap for ap in await self.get_ap_info() if ap["mac"] == mac), None)

    async def _find_wlan_by_ssid(self, ssid: str) -> dict:
        return next((wlan for wlan in await self.get_wlan_info() if wlan["ssid"] == ssid), None)

    async def cmdstat(self, data: str, collection_elements: List[str] = None) -> dict | List:
        result_text = await self._cmdstat_noparse(data)
        return self._ajaxunwrap(result_text, collection_elements)

    async def _cmdstat_noparse(self, data: str) -> str:
        return await self._ajaxpost(self.__cmdstat_url, data)

    async def conf(self, data: str, collection_elements: List[str] = None) -> dict | List:
        result_text = await self._conf_noparse(data)
        return self._ajaxunwrap(result_text, collection_elements)

    async def _conf_noparse(self, data: str) -> str:
        return await self._ajaxpost(self.__conf_url, data)

    @staticmethod
    def _ajaxunwrap(xml: str, collection_elements: List[str] = None) -> dict | List:
        # convert xml and unwrap collection
        force_list = None if not collection_elements else {ce: True for ce in collection_elements}
        result = xmltodict.parse(xml, encoding="utf-8", attr_prefix='', postprocessor=Ruckus._process_ruckus_ajax_xml, force_list=force_list)
        collection_list = [] if not collection_elements else [f"{ce}-list" for ce in collection_elements] + collection_elements
        for key in ["ajax-response", "response", "apstamgr-stat"] + collection_list:
            if result and key and key in result:
                result = result[key]
        return result or []

    @staticmethod
    def _process_ruckus_ajax_xml(path, key, value):
        if key.startswith("x-") and value:  # passphrases are obfuscated and stored with an x- prefix; decrypt these
            return key[2:], ''.join(chr(ord(letter) - 1) for letter in value)
        elif key == "apstamgr-stat" and not value:  # return an empty array rather than None, for ease of use
            return key, []
        elif key == "status" and value and value.isnumeric() and path and len(path) > 0 and path[-1][0] == "client":  # client status is numeric code for active, and name for inactive. Show name for everything
            description = "Authorized" if value == "1" else "Authenticating" if value == "2" else "PSK Expired" if value == "3" else "Authorized(Deny)" if value == "4" else "Authorized(Permit)" if value == "5" else "Unauthorized"
            return key, description
        else:
            return key, value

    @staticmethod
    def _normalize_mac(mac: str) -> str:
        if mac and match(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", string=mac, flags=IGNORECASE):
            return mac.replace('-', ':').lower()
        raise ValueError(VALUE_ERROR_INVALID_MAC)

    @staticmethod
    def _validate_passphrase(passphrase: str) -> str:
        if passphrase and match(r".*<.*>.*", string=passphrase):
            raise ValueError(VALUE_ERROR_INVALID_PASSPHRASE_JS)
        if passphrase and match(r"(^[!-~]([ -~]){6,61}[!-~]$)|(^([0-9a-fA-F]){64}$)", string=passphrase):
            return passphrase
        raise ValueError(VALUE_ERROR_INVALID_PASSPHRASE_LEN)

    async def __login(self) -> None:

        # create aiohttp session if we don't have one
        if not self.__session:
            self.__session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), cookie_jar=aiohttp.CookieJar(unsafe=True), connector=aiohttp.TCPConnector(keepalive_timeout=5))

        # locate the admin pages: /admin/* for Unleashed and ZD 9.x, /admin10/* for ZD 10.x
        async with self.__session.head(f"https://{self.host}", timeout=3, ssl=self.__ssl, allow_redirects=False) as h:
            self.__login_url = h.headers["Location"]
            self.__base_url = self.__login_url.rsplit('/', 1)[0]
            self.__cmdstat_url = self.__base_url + "/_cmdstat.jsp"
            self.__conf_url = self.__base_url + "/_conf.jsp"

        # login and collect CSRF token
        async with self.__session.head(self.__login_url, params={"username": self.username, "password": self.password, "ok": "Log In"}, timeout=3, ssl=self.__ssl, allow_redirects=False) as h:
            if h.status == 200:  # if username/password were valid we'd be redirected to the main admin page
                raise AuthenticationError(LOGIN_ERROR_LOGIN_INCORRECT)
            if "HTTP_X_CSRF_TOKEN" in h.headers:  # modern ZD and Unleashed return CSRF token in header
                self.__session.headers["X-CSRF-Token"] = h.headers["HTTP_X_CSRF_TOKEN"]
            else:  # older ZD and Unleashed require you to scrape the CSRF token from a page's javascript
                async with self.__session.get(self.__base_url + "/_csrfTokenVar.jsp", timeout=3, ssl=self.__ssl, allow_redirects=False) as r:
                    if r.status == 200:
                        csrf_token = xmltodict.parse(await r.text())["script"].split('=').pop()[2:12]
                        self.__session.headers["X-CSRF-Token"] = csrf_token
                    elif r.status == 500:  # even older ZD don't use CSRF tokens at all
                        pass
                    else:  # token page is a redirect, maybe temporary Unleashed Rebuilding placeholder page is showing
                        raise ConnectionRefusedError(CONNECT_ERROR_TEMPORARY)

    async def __logout(self) -> None:
        if self.__session:
            async with self.__session.head(self.__login_url, params={"logout": "1"}, timeout=3, ssl=self.__ssl, allow_redirects=False):
                await self.__session.close()

    async def _ajaxpost(self, cmd: str, data: str, retrying: bool = False) -> str:
        # request data
        async with self.__session.post(cmd, data=data, headers={"Content-Type": "text/xml"}, ssl=self.__ssl, allow_redirects=False) as r:
            if r.status == 302:  # if the session is dead then we're redirected to the login page
                if retrying:  # we tried logging in again, but the redirect still happens - maybe password changed?
                    raise PermissionError(AJAX_POST_REDIRECTED_ERROR)
                await self.__login()  # try logging in again, then retry post
                return await self._ajaxpost(cmd, data, retrying=True)
            result_text = await r.text()
            if not result_text or result_text == "\n":  # if the ajax request payload wasn't understood then we get an empty page back
                raise RuntimeError(AJAX_POST_NORESULT_ERROR)
            return result_text

    def __init__(self, host: str, username: str, password: str) -> None:
        self.host = host
        self.username = username
        self.password = password

        self.__login_url = None
        self.__base_url = None
        self.__cmdstat_url = None
        self.__conf_url = None
        self.__session = None

        # create ssl context so we ignore cert errors
        context = ssl.create_default_context()
        context.set_ciphers("DEFAULT")
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.__ssl = context

    async def __aenter__(self) -> "Ruckus":
        await self.__login()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.__logout()
