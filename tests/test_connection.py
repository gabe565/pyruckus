"""Test connecting to a device and issuing commands."""
import pytest

from pyruckus.exceptions import AuthenticationError
from tests import connect_ruckus


@pytest.mark.asyncio
async def test_connect_success():
    """Test that a normal connection works."""
    await connect_ruckus()

@pytest.mark.asyncio
async def test_authentication_error():
    """Test that AuthenticationError is thrown on invalid login."""
    with pytest.raises(AuthenticationError):
        await connect_ruckus(password="bad-pass")


@pytest.mark.asyncio
async def test_connection_error():
    """Test that ConnectionError is thrown on invalid host."""
    with pytest.raises(ConnectionError):
        await connect_ruckus(host="127.0.0.1")


@pytest.mark.asyncio
async def test_disconnect_success():
    """Test we can disconnect."""
    ruckus = await connect_ruckus()
    ruckus.disconnect()
