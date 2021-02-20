# pyruckus

A Python API which interacts with a Ruckus Unleashed device.

## Setup

To install the `pyruckus` package:

```sh
pip3 install pyruckus
```

## Usage

Each function is defined as an [async](https://docs.python.org/3/library/asyncio.html) function, so you will have to create an event loop instead of calling the functions directly in a shell.

```python
from pyruckus import Ruckus
import asyncio

async def test_pyruckus():
    ruckus = Ruckus("<ruckus ip>", "<ruckus user>", "<ruckus password>")
    await ruckus.connect()

    ap_info = await ruckus.ap_info()
    mesh_info = await ruckus.mesh_info()
    system_info = await ruckus.system_info()
    config = await ruckus.config()
    clients = await ruckus.current_active_clients()
    wlan_info = await ruckus.wlan_info()

    ruckus.disconnect()

loop = asyncio.get_event_loop()
loop.run_until_complete(test_pyruckus())
```

