from pyruckus import Ruckus
from .const import SERVER, USERNAME, PASSWORD


def test_clients_success():
    ruckus = Ruckus(SERVER, USERNAME, PASSWORD)
    clients = ruckus.clients()
    assert clients
