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
        self.connect()

    def __del__(self) -> None:
        """Disconnect on delete."""
        self.disconnect()

    def connect(self) -> None:
        """Create SSH connection and login."""
        ssh = RuckusSSH(encoding="utf-8")
        ssh.login(self.host, username=self.username, password=self.password, login_timeout=self.login_timeout)
        self.ssh = ssh

    def disconnect(self) -> None:
        """Close the SSH session."""
        if self.ssh and self.ssh.isalive():
            self.ssh.close()

    def mesh_name(self) -> str:
        """Pull the current mesh name."""
        try:
            return self.mesh_info()['Mesh Settings']['Mesh Name(ESSID)']
        except KeyError:
            return 'Ruckus Mesh'

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
                line = line[:-1].strip()
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
                key, _, value = line.partition("= ")
                if key:
                    node[key.strip()] = value.strip()

        return root

    def mesh_info(self) -> dict:
        """Pull the current mesh name."""
        if not self.ssh.isalive():
            self.connect()

        result = self.ssh.run_privileged("show mesh info")

        return self.__parse_kv(result)

    def system_info(self) -> dict:
        """Pull the system info."""
        if not self.ssh.isalive():
            self.connect()

        result = self.ssh.run_privileged("show sysinfo")

        return self.__parse_kv(result)

    def current_active_clients(self) -> dict:
        """Pull active clients from the device."""
        if not self.ssh.isalive():
            self.connect()

        result = self.ssh.run_privileged("show current-active-clients all")
        result, _, _ = result.partition("Last 300 Events/Activities:")

        return self.__parse_kv(result)

    def ap_info(self) -> dict:
        """Pull info about current access points."""
        if not self.ssh.isalive():
            self.connect()

        result = self.ssh.run_privileged("show ap all")

        return self.__parse_kv(result)
