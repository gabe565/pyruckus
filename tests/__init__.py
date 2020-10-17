"""Tests for pyruckus."""
from os import environ

from pyruckus import Ruckus

HOST = environ.get("RUCKUS_HOST")
USERNAME = environ.get("RUCKUS_USERNAME")
PASSWORD = environ.get("RUCKUS_PASSWORD")


async def connect_ruckus(host=HOST, username=USERNAME, password=PASSWORD):
    ruckus = Ruckus(host, username, password)
    await ruckus.connect()
    return ruckus
