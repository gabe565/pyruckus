"""Ruckus Ajax client. Using requests because httpx didn't like Ruckus out-of-spec http responses"""
import requests
import xmltodict

from .const import (
    LOGIN_ERROR_LOGIN_INCORRECT, AJAX_POST_NORESULT_ERROR, AJAX_POST_REDIRECTED_ERROR
)
from .exceptions import AuthenticationError


class RuckusAjax():
    """Ruckus Ajax client."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        
        self.__login_url = None
        self.__base_url = None
        self.__cmdstat_url = None
        self.__conf_url = None

        self.session = None

    async def login(self) -> None:
        """Log into the Ruckus device."""

        """Create http client"""
        s = requests.Session()
        s.verify = False
        self.session = s

        """Locate admin urls"""
        h = s.head(f"http://{self.host}", timeout=3)
        self.__login_url = h.headers["Location"].replace("http://", "https://")
        self.__base_url = self.__login_url.rsplit('/', 1)[0]
        self.__cmdstat_url = self.__base_url  + "/_cmdstat.jsp"
        self.__conf_url = self.__base_url  + "/_conf.jsp"

        """Login"""
        h = s.head(self.__login_url, params = { "username": self.username, "password": self.password, "ok": "Log In" }, timeout=3)
        if h.status_code == 200: # if username/password were valid we'd be redirected to the main admin page
            raise AuthenticationError(LOGIN_ERROR_LOGIN_INCORRECT)
        if "HTTP_X_CSRF_TOKEN" in h.headers: # newer ZD and Unleashed return CSRF token in header
            s.headers.update({ "X-CSRF-Token": h.headers["HTTP_X_CSRF_TOKEN"] })
        else: # older ZD and Unleashed require you to scrape the CSRF token from a page's javascript
            r = s.get(self.__base_url + "/_csrfTokenVar.jsp")
            if r.status_code != 200: # no token page, maybe temporary Unleashed Rebuilding placeholder is showing
                raise requests.exceptions.HTTPError(requests.codes['unavailable'])
            csrf_token = xmltodict.parse(r.text)["script"].split('=').pop()[2:12]
            s.headers.update({ "X-CSRF-Token": csrf_token })

    async def close(self) -> None:
        if self.session:
            h = self.session.head(self.__login_url, params = { "logout": "1" }, timeout=3)
            self.session.close()

    def __process_ruckus_ajax_xml(self, path, key, value):
        if key.startswith("x-") and value: # passphrases are obfuscated and stored with an x- prefix
            return key[2:], ''.join(chr(ord(letter)-1) for letter in value)
        elif key == "apstamgr-stat" and not value: # return an empty array rather than None, for ease of use
            return key, []
        else:
            return key, value

    async def __ajax_post(self, cmd: str, data: str, collection_element: str = None, retrying: bool = False) -> dict:

        # request data
        r = self.session.post(cmd, data=data, headers={ "Content-Type": "text/xml" })

        # check if we're being asked to login again
        if r.history: # if the session is dead then we're redirected to the login page
            if retrying: # we tried logging in again, but the redirect still happens - maybe password changed?
                raise PermissionError(AJAX_POST_REDIRECTED_ERROR)
            """Ruckus session timed-out. Logging in again."""
            self.session.close()
            self.login()
            return await self.__ajax_post(cmd, data, collection_element, retrying = True)

        if not r.text: # if the ajax request payload wasn't understood then we get an empty page back
            raise requests.exceptions.ContentDecodingError(AJAX_POST_NORESULT_ERROR)

        # convert xml and unwrap collection
        force_list = None if not collection_element else { collection_element: True }
        result = xmltodict.parse(r.text, encoding="utf-8", attr_prefix='', postprocessor=self.__process_ruckus_ajax_xml, force_list = force_list)
        for key in ("ajax-response", "response", "apstamgr-stat", collection_element):
            if result and key and key in result:
                result = result[key]
        return result or []

    async def cmd_stat(self, data: str, collection_element: str = None) -> dict:
        return await self.__ajax_post(self.__cmdstat_url, data, collection_element)

    async def conf(self, data: str, collection_element: str = None) -> dict:
        return await self.__ajax_post(self.__conf_url, data, collection_element)

