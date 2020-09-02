# pyruckus

A Python API which interacts with a Ruckus Unleashed device.

## Setup

To install the `pyruckus` package:

```sh
pip3 install pyruckus
```

## Usage

```python
>>> from pyruckus import Ruckus
>>> ruckus = Ruckus("host", "username", "password")
>>> ruckus.clients()
```

