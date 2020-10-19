import pytest

from tests import connect_ruckus


@pytest.mark.asyncio
async def test_current_active_clients():
    """Test we can get currently connected clients."""
    ruckus = await connect_ruckus()
    clients = await ruckus.current_active_clients()
    assert clients
    client = clients["current_active_clients"]["clients"][0]
    assert client["mac_address"]
    assert client["host_name"]
    assert client["user_ip"]
    assert client["access_point"]


@pytest.mark.asyncio
async def test_mesh_info():
    """Test we can get mesh info."""
    ruckus = await connect_ruckus()
    mesh_info = await ruckus.mesh_info()
    assert mesh_info["mesh_settings"]["mesh_status"]
    assert mesh_info["mesh_settings"]["mesh_name_essid"]
    assert mesh_info["zero_touch_mesh_pre_approved_serial_number_list"]["serial_number"]


@pytest.mark.asyncio
async def test_mesh_name():
    """Test we can get mesh name."""
    ruckus = await connect_ruckus()
    mesh_name = await ruckus.mesh_name()
    assert mesh_name


@pytest.mark.asyncio
async def test_system_info():
    """Test we can get system info."""
    ruckus = await connect_ruckus()
    system_info = await ruckus.system_info()
    assert system_info["system_overview"]["name"]
    assert system_info["system_overview"]["serial_number"]
    assert system_info["system_overview"]["version"]


@pytest.mark.asyncio
async def test_ap_info():
    """Test we can get access point info."""
    ruckus = await connect_ruckus()
    ap_info = await ruckus.ap_info()
    ap = ap_info["ap"]["id"]["1"]
    assert ap["mac_address"]
    assert ap["model"]
    assert ap["device_name"]
    assert ap["network_setting"]["gateway"]
