"""Unit tests for nautobot_device_lifecycle_mgmt."""
import datetime
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType

from nautobot.utilities.testing import APIViewTestCases
from nautobot.dcim.models import DeviceType, Manufacturer, Platform, Device, DeviceRole, InventoryItem, Site
from nautobot.extras.models import Status, Tag

from nautobot_device_lifecycle_mgmt.models import (
    HardwareLCM,
    SoftwareLCM,
    ContractLCM,
    ProviderLCM,
    ValidatedSoftwareLCM,
    CVELCM,
    VulnerabilityLCM,
    SoftwareImageLCM,
)
from nautobot_device_lifecycle_mgmt.tests.conftest import create_devices, create_cves, create_softwares


User = get_user_model()


class HardwareLCMAPITest(APIViewTestCases.APIViewTestCase):  # pylint: disable=too-many-ancestors
    """Test the HardwareLCM API."""

    model = HardwareLCM
    bulk_update_data = {"documentation_url": "https://cisco.com/eox"}
    brief_fields = [
        "custom_fields",
        "device_type",
        "display",
        "documentation_url",
        "end_of_sale",
        "end_of_security_patches",
        "end_of_support",
        "end_of_sw_releases",
        "expired",
        "id",
        "inventory_item",
        "release_date",
        "tags",
    ]

    @classmethod
    def setUpTestData(cls):
        """Create a superuser and token for API calls."""
        manufacturer = Manufacturer.objects.create(name="Cisco", slug="cisco")
        device_types = (
            DeviceType.objects.create(model="c9300-24", slug="c9300-24", manufacturer=manufacturer),
            DeviceType.objects.create(model="c9300-48", slug="c9300-48", manufacturer=manufacturer),
            DeviceType.objects.create(model="c9500-24", slug="c9500-24", manufacturer=manufacturer),
            DeviceType.objects.create(model="c9500-48", slug="c9500-48", manufacturer=manufacturer),
            DeviceType.objects.create(model="c9407", slug="c9407", manufacturer=manufacturer),
            DeviceType.objects.create(model="c9410", slug="c9410", manufacturer=manufacturer),
        )

        HardwareLCM.objects.create(device_type=device_types[3], end_of_sale=datetime.date(2021, 4, 1))
        HardwareLCM.objects.create(device_type=device_types[4], end_of_sale=datetime.date(2021, 4, 1))
        HardwareLCM.objects.create(device_type=device_types[5], end_of_sale=datetime.date(2021, 4, 1))

        cls.create_data = [
            # Setting end_of_sale as datetime.date for proper comparison
            {"device_type": device_types[0].id, "end_of_sale": datetime.date(2021, 4, 1)},
            {"device_type": device_types[1].id, "end_of_sale": datetime.date(2021, 4, 1)},
            {"device_type": device_types[2].id, "end_of_sale": datetime.date(2021, 4, 1)},
        ]

    def test_bulk_create_objects(self):
        """Currently don't support bulk operations."""

    def test_bulk_delete_objects(self):
        """Currently don't support bulk operations."""

    def test_bulk_update_objects(self):
        """Currently don't support bulk operations."""


class SoftwareLCMAPITest(APIViewTestCases.APIViewTestCase):  # pylint: disable=too-many-ancestors
    """Test the SoftwareLCM API."""

    model = SoftwareLCM
    brief_fields = [
        "device_platform",
        "display",
        "end_of_support",
        "id",
        "url",
        "version",
    ]

    @classmethod
    def setUpTestData(cls):

        device_platforms = (
            Platform.objects.create(name="Cisco IOS", slug="cisco_ios"),
            Platform.objects.create(name="Arista EOS", slug="arista_eos"),
            Platform.objects.create(name="Juniper Junos", slug="juniper_junos"),
        )

        cls.create_data = [
            {
                "device_platform": device_platforms[0].id,
                "version": "15.4(3)M",
                "end_of_support": datetime.date(2022, 2, 28),
            },
            {
                "device_platform": device_platforms[1].id,
                "version": "4.21.3F",
                "end_of_support": datetime.date(2021, 8, 9),
            },
            {
                "device_platform": device_platforms[2].id,
                "version": "20.3R3",
                "end_of_support": datetime.date(2023, 9, 29),
            },
        ]

        SoftwareLCM.objects.create(
            device_platform=device_platforms[0], version="15.1(2)M", end_of_support=datetime.date(2023, 5, 8)
        )
        SoftwareLCM.objects.create(
            device_platform=device_platforms[1], version="4.22.9M", end_of_support=datetime.date(2022, 4, 11)
        )
        SoftwareLCM.objects.create(
            device_platform=device_platforms[2], version="21.4R3", end_of_support=datetime.date(2024, 5, 19)
        )

    def test_bulk_create_objects(self):
        """Currently don't support bulk operations."""

    def test_bulk_delete_objects(self):
        """Currently don't support bulk operations."""

    def test_bulk_update_objects(self):
        """Currently don't support bulk operations."""


class ContractLCMAPITest(APIViewTestCases.APIViewTestCase):  # pylint: disable=too-many-ancestors
    """Test the ContractLCM API."""

    model = ContractLCM
    bulk_update_data = {"documentation_url": "https://cisco.com/eox"}
    brief_fields = [
        "contract_type",
        "cost",
        "display",
        "end",
        "expired",
        "id",
        "name",
        "provider",
        "start",
        "support_level",
    ]

    @classmethod
    def setUpTestData(cls):
        """Create a superuser and token for API calls."""
        provider = ProviderLCM.objects.create(
            name="Cisco",
            description="Cisco Support",
            physical_address="123 Cisco Way, San Jose, CA",
            phone="(123) 456-7890",
            email="email@cisco.com",
            portal_url="https://www.cisco.com/",
            comments="Test Comment",
        )
        cls.create_data = [
            {
                "name": "Nexus Support - Hardware",
                "start": datetime.date(2021, 4, 1),
                "end": datetime.date(2022, 4, 1),
                "support_level": "24/7",
                "contract_type": "Hardware",
                "provider": provider.id,
            },
            {
                "name": "Nexus Support - Software",
                "start": datetime.date(2021, 4, 1),
                "end": datetime.date(2022, 4, 1),
                "support_level": "8-5, M-F",
                "contract_type": "Software",
                "provider": provider.id,
            },
            {
                "name": "ASA Support - Hardware",
                "start": datetime.date(2021, 4, 1),
                "end": datetime.date(2022, 4, 1),
                "support_level": "24/7",
                "contract_type": "Hardware",
                "provider": provider.id,
            },
        ]

        ContractLCM.objects.create(
            name="Meraki Hardware Support",
            number="MERK00001",
            start=datetime.date(2021, 4, 1),
            end=datetime.date(2022, 4, 1),
            provider=provider,
        )
        ContractLCM.objects.create(
            name="Meraki Software Support",
            number="MERK00002",
            start=datetime.date(2021, 4, 1),
            end=datetime.date(2022, 4, 1),
            provider=provider,
        )
        ContractLCM.objects.create(
            name="Juniper Hardware Support",
            number="CSCO0000001",
            start=datetime.date(2021, 4, 1),
            end=datetime.date(2022, 4, 1),
            provider=provider,
        )

    def test_bulk_create_objects(self):
        """Currently don't support bulk operations."""

    def test_bulk_delete_objects(self):
        """Currently don't support bulk operations."""

    def test_bulk_update_objects(self):
        """Currently don't support bulk operations."""


class ValidatedSoftwareLCMAPITest(APIViewTestCases.APIViewTestCase):  # pylint: disable=too-many-ancestors
    """Test the SoftwareLCM API."""

    model = ValidatedSoftwareLCM
    brief_fields = [
        "custom_fields",
        "device_roles",
        "device_types",
        "devices",
        "display",
        "end",
        "id",
        "inventory_items",
        "object_tags",
        "preferred",
        "software",
        "start",
        "tags",
        "url",
        "valid",
    ]

    @classmethod
    def setUpTestData(cls):
        """Create a superuser and token for API calls."""
        device_platform = Platform.objects.create(name="Cisco IOS", slug="cisco_ios")
        softwares = (
            SoftwareLCM.objects.create(
                **{
                    "device_platform": device_platform,
                    "version": "17.3.3 MD",
                    "alias": "Amsterdam-17.3.3 MD",
                    "end_of_support": "2022-05-15",
                    "documentation_url": "https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-15-4m-t/series.html",
                    "long_term_support": True,
                    "pre_release": False,
                }
            ),
            SoftwareLCM.objects.create(
                **{
                    "device_platform": device_platform,
                    "version": "15.5(1)SY",
                    "alias": "Catalyst-15.5(1)SY",
                    "end_of_support": "2019-02-5",
                    "documentation_url": "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/15-1SY/config_guide/sup2T/15_1_sy_swcg_2T/cef.html",
                    "long_term_support": False,
                    "pre_release": True,
                }
            ),
        )

        status_active = Status.objects.get(slug="active")
        manufacturer = Manufacturer.objects.create(name="Cisco", slug="cisco")
        site = Site.objects.create(name="Site 1", slug="site-1")
        deviceroles = (
            DeviceRole.objects.create(name="Router", slug="router", color="ff0000"),
            DeviceRole.objects.create(name="Switch", slug="switch", color="ffff00"),
        )
        devicetypes = (
            DeviceType.objects.create(manufacturer=manufacturer, model="ASR-1000", slug="asr-1000"),
            DeviceType.objects.create(manufacturer=manufacturer, model="Catalyst 6500", slug="catalyst-6500"),
        )
        devices = (
            Device.objects.create(
                device_type=devicetypes[0], device_role=deviceroles[0], name="Device 1", site=site, status=status_active
            ),
            Device.objects.create(
                device_type=devicetypes[1], device_role=deviceroles[1], name="Device 2", site=site, status=status_active
            ),
        )
        inventoryitems = (
            InventoryItem.objects.create(device=devices[0], name="SwitchModule1"),
            InventoryItem.objects.create(device=devices[1], name="Supervisor Engine 720"),
        )

        cls.create_data = [
            {
                "software": softwares[0].id,
                "devices": [device.pk for device in devices],
                "start": datetime.date(2020, 1, 14),
                "end": datetime.date(2024, 10, 18),
                "preferred": False,
            },
            {
                "software": softwares[0].id,
                "device_types": [devicetype.pk for devicetype in devicetypes],
                "start": datetime.date(2021, 6, 4),
                "end": datetime.date(2025, 1, 8),
                "preferred": True,
            },
            {
                "software": softwares[0].id,
                "device_roles": [devicerole.pk for devicerole in deviceroles],
                "start": datetime.date(2019, 3, 6),
                "end": datetime.date(2023, 6, 1),
                "preferred": False,
            },
            {
                "software": softwares[0].id,
                "inventory_items": [inventoryitem.pk for inventoryitem in inventoryitems],
                "start": datetime.date(2019, 5, 4),
                "end": datetime.date(2023, 9, 15),
                "preferred": False,
            },
        ]

        validated_software = ValidatedSoftwareLCM(
            software=softwares[1],
            start=datetime.date(2021, 6, 4),
            end=datetime.date(2025, 1, 8),
            preferred=True,
        )
        validated_software.devices.set([device.pk for device in devices])
        validated_software.save()

        validated_software = ValidatedSoftwareLCM(
            software=softwares[1],
            start=datetime.date(2018, 2, 23),
            end=datetime.date(2019, 6, 12),
            preferred=False,
        )
        validated_software.device_types.set([devicetype.pk for devicetype in devicetypes])
        validated_software.save()

        validated_software = ValidatedSoftwareLCM(
            software=softwares[1],
            start=datetime.date(2019, 11, 19),
            end=datetime.date(2030, 7, 30),
            preferred=False,
        )
        validated_software.device_roles.set([devicerole.pk for devicerole in deviceroles])
        validated_software.save()

        ValidatedSoftwareLCM(
            software=softwares[1],
            start=datetime.date(2020, 10, 9),
            end=datetime.date(2025, 1, 16),
            preferred=False,
        )
        validated_software.inventory_items.set([inventoryitem.pk for inventoryitem in inventoryitems])
        validated_software.save()

    def test_bulk_create_objects(self):
        """Currently don't support bulk operations."""

    def test_bulk_delete_objects(self):
        """Currently don't support bulk operations."""

    def test_bulk_update_objects(self):
        """Currently don't support bulk operations."""


class CVELCMAPITest(APIViewTestCases.APIViewTestCase):  # pylint: disable=too-many-ancestors
    """Test the CVELCM API."""

    model = CVELCM
    brief_fields = [
        "comments",
        "cvss",
        "cvss_v2",
        "cvss_v3",
        "description",
        "display",
        "fix",
        "id",
        "last_modified_date",
        "link",
        "name",
        "published_date",
        "severity",
        "status",
        "url",
    ]

    @classmethod
    def setUpTestData(cls):

        cls.create_data = [
            {
                "name": "CVE-2021-40128",
                "published_date": datetime.date(2021, 11, 4),
                "last_modified_date": datetime.date(2021, 12, 4),
                "link": "https://www.cvedetails.com/cve/CVE-2021-40128/",
            },
            {
                "name": "CVE-2021-40126",
                "published_date": datetime.date(2021, 11, 4),
                "last_modified_date": datetime.date(2022, 2, 4),
                "link": "https://www.cvedetails.com/cve/CVE-2021-40126/",
            },
            {
                "name": "CVE-2021-40125",
                "published_date": datetime.date(2021, 10, 27),
                "last_modified_date": datetime.date(2022, 1, 4),
                "link": "https://www.cvedetails.com/cve/CVE-2021-40125/",
            },
        ]

        CVELCM.objects.create(
            name="CVE-2021-1391",
            published_date="2021-03-24",
            last_modified_date="2021-12-04",
            link="https://www.cvedetails.com/cve/CVE-2021-1391/",
        )
        CVELCM.objects.create(
            name="CVE-2021-44228",
            published_date="2021-12-10",
            last_modified_date="2021-12-14",
            link="https://www.cvedetails.com/cve/CVE-2021-44228/",
        )
        CVELCM.objects.create(
            name="CVE-2020-27134",
            published_date="2020-12-11",
            last_modified_date="2021-01-04",
            link="https://www.cvedetails.com/cve/CVE-2020-27134/",
        )

    def test_bulk_create_objects(self):
        """Currently don't support bulk operations."""

    def test_bulk_delete_objects(self):
        """Currently don't support bulk operations."""

    def test_bulk_update_objects(self):
        """Currently don't support bulk operations."""


class VulnerabilityLCMAPITest(
    # Not inheriting CreateObjectViewTestCase
    APIViewTestCases.GetObjectViewTestCase,
    APIViewTestCases.ListObjectsViewTestCase,
    APIViewTestCases.UpdateObjectViewTestCase,
    APIViewTestCases.DeleteObjectViewTestCase,
):  # pylint: disable=too-many-ancestors
    """Test the VulnerabilityLCM API."""

    model = VulnerabilityLCM
    brief_fields = [
        "custom_fields",
        "cve",
        "device",
        "display",
        "id",
        "inventory_item",
        "software",
        "status",
        "tags",
        "url",
    ]
    validation_excluded_fields = ["status"]

    @classmethod
    def setUpTestData(cls):
        devices = create_devices()
        cves = create_cves()
        softwares = create_softwares()

        for i, cve in enumerate(cves):
            VulnerabilityLCM.objects.create(cve=cve, device=devices[i], software=softwares[i])

        vuln_ct = ContentType.objects.get_for_model(VulnerabilityLCM)
        status = Status.objects.create(name="Exempt", slug="exempt", color="4caf50", description="This unit is exempt.")
        status.content_types.set([vuln_ct])
        cls.create_data = [{"status": "exempt"}]

    def test_bulk_delete_objects(self):
        """Currently don't support bulk operations."""

    def test_bulk_update_objects(self):
        """Currently don't support bulk operations."""

    def test_options_returns_expected_choices(self):
        """Disabling inherited test that uses POST."""

    def test_options_objects_returns_display_and_value(self):
        """Disabling inherited test that uses POST."""


class SoftwareImageLCMAPITest(APIViewTestCases.APIViewTestCase):  # pylint: disable=too-many-ancestors
    """Test the SoftwareImageLCM API."""

    model = SoftwareImageLCM
    brief_fields = [
        "default_image",
        "device_types",
        "display",
        "download_url",
        "id",
        "image_file_checksum",
        "image_file_name",
        "inventory_items",
        "object_tags",
        "url",
    ]

    @classmethod
    def setUpTestData(cls):  # pylint: disable=too-many-locals
        """Create a superuser and token for API calls."""
        device_platform_cisco, _ = Platform.objects.get_or_create(name="Cisco IOS", slug="cisco_ios")
        device_platform_arista, _ = Platform.objects.get_or_create(name="Arista EOS", slug="arista_eos")
        softwares_cisco = (
            SoftwareLCM.objects.get_or_create(
                **{
                    "device_platform": device_platform_cisco,
                    "version": "17.3.3 MD",
                }
            )[0],
            SoftwareLCM.objects.get_or_create(
                **{
                    "device_platform": device_platform_cisco,
                    "version": "15.5(1)SY",
                }
            )[0],
        )
        softwares_arista = (
            SoftwareLCM.objects.get_or_create(
                **{
                    "device_platform": device_platform_arista,
                    "version": "4.21.6M",
                }
            )[0],
            SoftwareLCM.objects.get_or_create(
                **{
                    "device_platform": device_platform_arista,
                    "version": "4.25.7F",
                }
            )[0],
        )

        status_active = Status.objects.get(slug="active")
        manufacturer_cisco = Manufacturer.objects.create(name="Cisco", slug="cisco")
        manufacturer_arista = Manufacturer.objects.create(name="Arista", slug="arista")
        site = Site.objects.create(name="Site 1", slug="site-1")
        devicerole = DeviceRole.objects.create(name="Router", slug="router", color="ff0000")
        devicetypes_cisco = (
            DeviceType.objects.create(manufacturer=manufacturer_cisco, model="ASR-1000", slug="asr-1000"),
            DeviceType.objects.create(manufacturer=manufacturer_cisco, model="Catalyst 6500", slug="catalyst-6500"),
        )
        devicetypes_arista = (
            DeviceType.objects.create(manufacturer=manufacturer_arista, model="7150S", slug="7150s"),
            DeviceType.objects.create(manufacturer=manufacturer_arista, model="7508R", slug="7508r"),
        )
        device_cisco = Device.objects.create(
            device_type=devicetypes_cisco[0], device_role=devicerole, name="Device 1", site=site, status=status_active
        )
        device_arista = Device.objects.create(
            device_type=devicetypes_arista[0], device_role=devicerole, name="Device 2", site=site, status=status_active
        )
        inventoryitems_cisco = (
            InventoryItem.objects.create(device=device_cisco, name="SwitchModule1"),
            InventoryItem.objects.create(device=device_cisco, name="Supervisor Engine 720"),
        )
        inventoryitems_arista = (
            InventoryItem.objects.create(device=device_arista, name="SFP1"),
            InventoryItem.objects.create(device=device_arista, name="QSFP1"),
        )

        tags = (Tag.objects.create(name="asr", slug="asr"), Tag.objects.create(name="edge", slug="edge"))

        cls.create_data = [
            {
                "image_file_name": "asr1001x-universalk9.17.03.03.SPA.bin",
                "software": softwares_cisco[0].id,
                "device_types": [devicetype.pk for devicetype in devicetypes_cisco],
                "download_url": "ftp://device-images.local.com/cisco/asr1001x-universalk9.17.03.03.SPA.bin",
                "image_file_checksum": "9cf2e09b59207a4d8ea408ea9971f6ae6facab9a1855a34e1ed8755f3ffe4b9e14",
                "default_image": True,
            },
            {
                "image_file_name": "asr1001x-universalk9.17.03.03.ssl.SPA.bin",
                "software": softwares_cisco[0].id,
                "inventory_items": [inventoryitem.pk for inventoryitem in inventoryitems_cisco],
                "download_url": "ftp://device-images.local.com/cisco/asr1001x-universalk9.17.03.03.ssl.SPA.bin",
                "image_file_checksum": "7f2e09b59207a4d8ea40fa132va71f6ae6facab9a1851a34e1ed8755f3ffe4b9e14",
                "default_image": False,
            },
            {
                "image_file_name": "s2t54-ipservicesk9_npe-mz.SPA.155-1.SY1.bin",
                "software": softwares_cisco[1].id,
                "object_tags": [tag.pk for tag in tags],
                "download_url": "ftp://device-images.local.com/cisco/s2t54-ipservicesk9_npe-mz.SPA.155-1.SY1.bin",
                "image_file_checksum": "74e61320f5518a2954b2d307b7e6a038",
                "default_image": True,
            },
        ]
        software_image = SoftwareImageLCM(
            image_file_name="eos2gb_4.21.6m.swi",
            software=softwares_arista[0],
            download_url="ftp://images.local/arista/eos2gb_4.21m.swi",
            image_file_checksum="78arfabd75b0fa2vzas1e7afcc6faa3fc",
            default_image=True,
        )
        software_image.save()
        software_image = SoftwareImageLCM(
            image_file_name="eos_4.21.6m.swi",
            software=softwares_arista[0],
            download_url="ftp://images.local/arista/eos_4.21.6m.swi",
            image_file_checksum="78arfabd75b0fa2vzas1e7a7ac6faa3fc",
            default_image=True,
        )
        software_image.inventory_items.set([inventoryitem.pk for inventoryitem in inventoryitems_arista])
        software_image.save()

        software_image = SoftwareImageLCM(
            image_file_name="eos_4.25.7f.swi",
            software=softwares_arista[1],
            download_url="ftp://images.local/arista/eos_4.25.7f.swi",
            image_file_checksum="78arfabd75b0fa2vfas1e7a7ac6faa3fc",
            default_image=True,
        )
        software_image.device_types.set([devicetype.pk for devicetype in devicetypes_arista])
        software_image.save()

    def test_bulk_create_objects(self):
        """Currently don't support bulk operations."""

    def test_bulk_delete_objects(self):
        """Currently don't support bulk operations."""

    def test_bulk_update_objects(self):
        """Currently don't support bulk operations."""
