import pytest

from pyruckus import Ruckus
from .const import SERVER, USERNAME, PASSWORD


@pytest.fixture
def ruckus():
    return Ruckus(SERVER, USERNAME, PASSWORD)


def test_connect_success(ruckus):
    assert ruckus.ssh.isalive()


def test_disconnect_success(ruckus):
    ruckus.disconnect()
    assert not ruckus.ssh.isalive()


def test_enable_success(ruckus):
    ruckus.ssh.enable()
