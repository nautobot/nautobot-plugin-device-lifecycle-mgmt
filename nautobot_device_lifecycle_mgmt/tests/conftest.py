"""Params for testing."""
from nautobot.dcim.models import DeviceType, Manufacturer, Platform, Site, Device, DeviceRole, InventoryItem
from nautobot.extras.models import Status

from nautobot_device_lifecycle_mgmt.models import CVELCM, SoftwareLCM


def create_devices():
    """Create devices for tests."""
    device_platform, _ = Platform.objects.get_or_create(name="Cisco IOS", slug="cisco_ios")
    manufacturer, _ = Manufacturer.objects.get_or_create(slug="cisco")
    device_type = DeviceType.objects.create(manufacturer=manufacturer, model="6509-E", slug="6509-e")
    device_role = DeviceRole.objects.create(name="Core Switch", slug="core-switch")
    site = Site.objects.create(name="Test 1", slug="test-1")
    status_active = Status.objects.get(slug="active")

    return (
        Device.objects.create(
            name="sw1",
            platform=device_platform,
            device_type=device_type,
            device_role=device_role,
            site=site,
            status=status_active,
        ),
        Device.objects.create(
            name="sw2",
            platform=device_platform,
            device_type=device_type,
            device_role=device_role,
            site=site,
            status=status_active,
        ),
        Device.objects.create(
            name="sw3",
            platform=device_platform,
            device_type=device_type,
            device_role=device_role,
            site=site,
            status=status_active,
        ),
    )


def create_inventory_items():
    """Create inventory items for tests."""
    devices = create_devices()
    manufacturer, _ = Manufacturer.objects.get_or_create(slug="cisco")

    return (
        InventoryItem.objects.create(
            device=devices[0],
            manufacturer=manufacturer,
            name="SUP2T Card",
            part_id="VS-S2T-10G",
        ),
        InventoryItem.objects.create(
            device=devices[1],
            manufacturer=manufacturer,
            name="100GBASE-SR4 QSFP Transceiver",
            part_id="QSFP-100G-SR4-S",
        ),
        InventoryItem.objects.create(
            device=devices[2],
            manufacturer=manufacturer,
            name="48x RJ-45 Line Card",
            part_id="WS-X6548-GE-TX",
        ),
    )


def create_cves():
    """Create CVELCM items for tests."""
    cves = (
        CVELCM.objects.create(
            name="CVE-2021-1391",
            published_date="2021-03-24",
            link="https://www.cvedetails.com/cve/CVE-2021-1391/",
        ),
        CVELCM.objects.create(
            name="CVE-2021-44228",
            published_date="2021-12-10",
            link="https://www.cvedetails.com/cve/CVE-2021-44228/",
        ),
        CVELCM.objects.create(
            name="CVE-2020-27134",
            published_date="2020-12-11",
            link="https://www.cvedetails.com/cve/CVE-2020-27134/",
        ),
    )
    return cves


def create_softwares():
    """Create SoftwareLCM items for tests."""
    device_platform_ios, _ = Platform.objects.get_or_create(name="Cisco IOS", slug="cisco_ios")
    device_platform_eos, _ = Platform.objects.get_or_create(name="Arista EOS", slug="arista_eos")
    softwares = (
        SoftwareLCM.objects.create(device_platform=device_platform_ios, version="15.1(2)M"),
        SoftwareLCM.objects.create(device_platform=device_platform_ios, version="4.22.9M"),
        SoftwareLCM.objects.create(device_platform=device_platform_ios, version="21.4R3"),
        SoftwareLCM.objects.create(device_platform=device_platform_eos, version="4.17.1M"),
        SoftwareLCM.objects.create(device_platform=device_platform_eos, version="4.25.1F"),
    )
    return softwares
