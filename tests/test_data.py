from pyruckus import Ruckus
from .const import HOST, USERNAME, PASSWORD


def test_clients_success():
    ruckus = Ruckus(HOST, USERNAME, PASSWORD)
    clients = ruckus.clients()
    assert clients
