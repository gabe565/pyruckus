from pexpect import spawn, TIMEOUT, EOF

from .const import CONNECT_ERROR_EOF, CONNECT_ERROR_TIMEOUT, LOGIN_ERROR_LOGIN_INCORRECT


class LoginError(Exception):
    """Invalid login."""
    pass


class RuckusSSH(spawn):
    """Ruckus SSH client."""

    def __init__(self, timeout=30, maxread=2000, searchwindowsize=None,
                 logfile=None, cwd=None, env=None, ignore_sighup=True, echo=True,
                 encoding=None, codec_errors='strict', use_poll=False):

        spawn.__init__(self, None, timeout=timeout, maxread=maxread,
                       searchwindowsize=searchwindowsize, logfile=logfile,
                       cwd=cwd, env=env, ignore_sighup=ignore_sighup, echo=echo,
                       encoding=encoding, codec_errors=codec_errors, use_poll=use_poll)

    def login(self, host, username=None, password='', login_timeout=10):
        """Takes the host, username, and password, and logs into the Ruckus device."""
        spawn._spawn(self, f"ssh {host}")

        login_regex_array = ["Please login: ", "(?i)are you sure you want to continue connecting", EOF, TIMEOUT]

        i = self.expect(login_regex_array, timeout=login_timeout)
        if i == 1:
            # New certificate -- always accept it.
            # This is what you get if SSH does not have the remote host's
            # public key stored in the 'known_hosts' cache.
            self.sendline("yes")
            i = self.expect(login_regex_array, timeout=login_timeout)
        if i == 2:
            raise ConnectionError(CONNECT_ERROR_EOF)
        if i == 3:
            raise ConnectionError(CONNECT_ERROR_TIMEOUT)

        self.sendline(username)

        self.expect("Password: ")
        self.sendline(password)

        i = self.expect(["> ", "Login incorrect"])
        if i == 1:
            raise LoginError(LOGIN_ERROR_LOGIN_INCORRECT)

        return True

    def prompt(self, timeout=-1):
        """Wait for prompt and determine the current level of permissions."""
        if timeout == -1:
            timeout = self.timeout
        i = self.expect(["> ", "# ", TIMEOUT], timeout=timeout)
        if i == 2:
            raise ConnectionError(CONNECT_ERROR_TIMEOUT)
        return i

    def enable(self, force=False):
        """Enable privileged commands"""
        cmd = "enable"
        if force:
            cmd += " force"

        self.sendline(cmd)
        self.prompt()
