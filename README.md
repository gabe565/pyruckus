# pyruckus

A Python API which interacts with Ruckus Unleashed and ZoneDirector devices.

## Setup

To install the `pyruckus` package:

```sh
pip3 install pyruckus
```

## Usage

Each function is defined as an [async](https://docs.python.org/3/library/asyncio.html) [context manager](https://docs.python.org/3/reference/datamodel.html#context-managers), so you will have to create an event loop instead of calling the functions directly in a shell.

```python
from pyruckus import Ruckus, SystemStat
import asyncio

async def test_pyruckus():
    
    async with Ruckus("<ruckus ip>", "<ruckus user>", "<ruckus password>") as ruckus:

        wlans = await ruckus.get_wlan_info()
        wlan_groups = await ruckus.get_wlan_group_info()
        aps = await ruckus.get_ap_info()
        ap_groups = await ruckus.get_ap_group_info()
        mesh = await ruckus.get_mesh_info()
        default_system_info = await ruckus.get_system_info()
        all_system_info = await ruckus.get_system_info(SystemStat.ALL)
        active_clients = await ruckus.get_active_client_info()
        inactive_clients = await ruckus.get_inactive_client_info() # empty on Unleashed
        blocked = await ruckus.get_blocked_info()

        await ruckus.do_block_client("60:ab:de:ad:be:ef")
        await ruckus.do_unblock_client("60:ab:de:ad:be:ef")

        await ruckus.do_hide_ap_leds("24:79:de:ad:be:ef")
        await ruckus.do_show_ap_leds("24:79:de:ad:be:ef")

        await ruckus.do_disable_wlan("my ssid")
        await ruckus.do_enable_wlan("my ssid")

        await ruckus.do_set_wlan_password("my ssid", "blah>blah<")

asyncio.run(test_pyruckus())
```
