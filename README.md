# pyruckus

A Python API which interacts with a Ruckus Unleashed and ZoneDirector devices.

## Setup

To install the `pyruckus` package:

```sh
pip3 install pyruckus
```

## Usage

Each function is defined as an [async](https://docs.python.org/3/library/asyncio.html) function, so you will have to create an event loop instead of calling the functions directly in a shell.

```python
from pyruckus import Ruckus, SystemStat
import asyncio

async def test_pyruckus():
    ruckus = Ruckus("<ruckus ip>", "<ruckus user>", "<ruckus password>")
    await ruckus.connect()

    wlans = await ruckus.get_wlan_info()
    wlan_groups = await ruckus.get_wlan_group_info()
    aps = await ruckus.get_ap_info()
    ap_groups = await ruckus.get_ap_group_info()
    mesh = await ruckus.get_mesh_info()
    default_system_info = await ruckus.get_system_info()
    all_system_info = await ruckus.get_system_info(SystemStat.ALL)
    clients = await ruckus.get_active_client_info()
    blocked = await ruckus.get_blocked_info()
    await ruckus.do_block_client("60:ab:de:ad:be:ef")
    more_blocked = await ruckus.get_blocked_info()
    await ruckus.do_unblock_client("60:ab:de:ad:be:ef")

    ruckus.disconnect()

loop = asyncio.get_event_loop()
loop.run_until_complete(test_pyruckus())
```
