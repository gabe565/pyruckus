"""Ruckus SSH client."""
from pexpect import spawn, TIMEOUT, EOF

from .const import (
    CONNECT_ERROR_EOF,
    CONNECT_ERROR_TIMEOUT,
    LOGIN_ERROR_LOGIN_INCORRECT,
    CONNECT_ERROR_PRIVILEGED_ALREADY_LOGGED_IN,
    CMD_ENABLE,
    CMD_ENABLE_FORCE,
    CMD_DISABLE,
)
from .exceptions import AuthenticationError


class RuckusSSH(spawn):
    """Ruckus SSH client."""

    def __init__(
        self,
        timeout=30,
        ignore_sighup=True,
        encoding="utf-8",
    ) -> None:
        """Ruckus SSH client constructor."""
        spawn.__init__(
            self,
            None,
            timeout=timeout,
            ignore_sighup=ignore_sighup,
            encoding=encoding,
        )

    async def login(
        self, host: str, username=None, password="", login_timeout=10
    ) -> bool:
        """Log into the Ruckus device."""
        spawn._spawn(self, f"ssh {host}")

        login_regex_array = [
            "Please login: ",
            "(?i)are you sure you want to continue connecting",
            EOF,
            TIMEOUT,
        ]

        i = await self.expect(login_regex_array, timeout=login_timeout, async_=True)
        if i == 1:
            # New certificate -- always accept it.
            # This is what you get if SSH does not have the remote host's
            # public key stored in the 'known_hosts' cache.
            self.sendline("yes")
            i = await self.expect(login_regex_array, timeout=login_timeout, async_=True)
        if i == 2:
            raise ConnectionError(CONNECT_ERROR_EOF)
        if i == 3:
            raise ConnectionError(CONNECT_ERROR_TIMEOUT)

        self.sendline(username)

        await self.expect("Password: ", async_=True)
        self.sendline(password)

        i = await self.expect(["> ", "Login incorrect"], async_=True)
        if i == 1:
            raise AuthenticationError(LOGIN_ERROR_LOGIN_INCORRECT)

        return True

    async def run(self, cmd: str) -> str:
        """Run a command."""
        self.sendline(cmd)
        await self.expect("\n", async_=True)
        await self.prompt()
        return self.before

    async def run_privileged(self, cmd: str) -> str:
        """Run a privileged command."""
        await self.enable()
        result = await self.run(cmd)
        await self.disable()
        return result

    async def prompt(self, timeout=-1) -> int:
        """Wait for prompt and determine the current level of permissions."""
        if timeout == -1:
            timeout = self.timeout
        i = await self.expect(
            [
                "ruckus> ",
                "ruckus# ",
                "A privileged user is already logged in",
                EOF,
                TIMEOUT,
            ],
            timeout=timeout,
            async_=True,
        )
        if i == 2:
            await self.prompt(timeout)
            raise ConnectionError(CONNECT_ERROR_PRIVILEGED_ALREADY_LOGGED_IN)
        if i == 3:
            raise ConnectionError(CONNECT_ERROR_EOF)
        if i == 4:
            raise ConnectionError(CONNECT_ERROR_TIMEOUT)
        return i

    async def enable(self, force=False) -> None:
        """Enable privileged commands."""
        if force:
            cmd = f"{CMD_ENABLE} {CMD_ENABLE_FORCE}"
        else:
            cmd = CMD_ENABLE

        self.sendline(cmd)
        await self.prompt()

    async def disable(self) -> None:
        """Disable privileged commands."""
        self.sendline(CMD_DISABLE)
        await self.prompt()
