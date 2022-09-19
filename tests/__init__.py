"""Tests for pyruckus."""
from os import environ

from pyruckus import Ruckus

HOST = environ.get("RUCKUS_HOST", "127.0.0.1")
PORT = environ.get("RUCKUS_PORT", "2222")
USERNAME = environ.get("RUCKUS_USERNAME", "user")
PASSWORD = environ.get("RUCKUS_PASSWORD", "pass")


async def connect_ruckus(host=HOST, port=PORT, username=USERNAME, password=PASSWORD):
    """Connect to a ruckus device with configured values."""
    return await Ruckus.create(host, username, password, port=port)
