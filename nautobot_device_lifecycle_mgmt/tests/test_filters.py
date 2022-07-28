"""Test filters for lifecycle management."""
from datetime import date

from django.test import TestCase
from django.contrib.contenttypes.models import ContentType
import time_machine

from nautobot.dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site, Platform
from nautobot.extras.models import Status

from nautobot_device_lifecycle_mgmt.models import (
    HardwareLCM,
    SoftwareLCM,
    ValidatedSoftwareLCM,
    DeviceSoftwareValidationResult,
    InventoryItemSoftwareValidationResult,
    CVELCM,
    VulnerabilityLCM,
    SoftwareImageLCM,
)
from nautobot_device_lifecycle_mgmt.filters import (
    HardwareLCMFilterSet,
    SoftwareLCMFilterSet,
    ValidatedSoftwareLCMFilterSet,
    DeviceSoftwareValidationResultFilterSet,
    InventoryItemSoftwareValidationResultFilterSet,
    CVELCMFilterSet,
    VulnerabilityLCMFilterSet,
    SoftwareImageLCMFilterSet,
)
from .conftest import create_devices, create_inventory_items, create_cves, create_softwares


class HardwareLCMTestCase(TestCase):
    """Tests for HardwareLCMFilter."""

    queryset = HardwareLCM.objects.all()
    filterset = HardwareLCMFilterSet

    def setUp(self):
        self.manufacturer = Manufacturer.objects.create(name="Cisco", slug="cisco")
        self.device_types = (
            DeviceType.objects.create(model="c9300-24", slug="c9300-24", manufacturer=self.manufacturer),
            DeviceType.objects.create(model="c9300-48", slug="c9300-48", manufacturer=self.manufacturer),
        )
        self.device_role = DeviceRole.objects.create(name="Core Switch", slug="core-switch")
        self.site = Site.objects.create(name="Test 1", slug="test-1")
        self.devices = (
            Device.objects.create(
                name="r1",
                device_type=self.device_types[0],
                device_role=self.device_role,
                site=self.site,
            ),
            Device.objects.create(
                name="r2",
                device_type=self.device_types[1],
                device_role=self.device_role,
                site=self.site,
            ),
        )
        self.notices = (
            HardwareLCM.objects.create(
                device_type=self.device_types[0],
                end_of_sale="2022-04-01",
                end_of_support="2023-04-01",
                end_of_sw_releases="2024-04-01",
                end_of_security_patches="2025-04-01",
                documentation_url="https://cisco.com/c9300-24",
            ),
            HardwareLCM.objects.create(
                device_type=self.device_types[1],
                end_of_sale="2024-04-01",
                end_of_support="2025-05-01",
                end_of_sw_releases="2026-05-01",
                end_of_security_patches="2027-05-01",
                documentation_url="https://cisco.com/c9300-48",
            ),
        )

    def test_q_one_eo_sale(self):
        """Test q filter to find single record based on end_of_sale."""
        params = {"q": "2022"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_q_one_eo_support(self):
        """Test q filter to find single record based on end_of_support."""
        params = {"q": "2024"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_q_both_eo_sale_support(self):
        """Test q filter to both records."""
        params = {"q": "04-01"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_eo_sale(self):
        """Test end_of_sale filter."""
        params = {"end_of_sale": "2022-04-01"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_eo_support(self):
        """Test end_of_support filter."""
        params = {"end_of_support": "2025-05-01"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_eo_sw_releases(self):
        """Test end_of_sw_releases filter."""
        params = {"end_of_sw_releases": "2024-04-01"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_eo_security_patches(self):
        """Test end_of_security_patches filter."""
        params = {"end_of_security_patches": "2027-05-01"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_documentation_url(self):
        """Test notice filter."""
        params = {"documentation_url": "https://cisco.com/c9300-48"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_device_type_slug_single(self):
        """Test device_type filter."""
        params = {"device_type": ["c9300-24"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_device_types_slug_all(self):
        """Test device_type filter."""
        params = {"device_type": ["c9300-24", "c9300-48"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_device_types_id_single(self):
        """Test device_type_id filter."""
        params = {"device_type_id": [self.device_types[0].id]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_device_types_id_all(self):
        """Test device_type_id filter."""
        params = {"device_type_id": [self.device_types[0].id, self.device_types[1].id]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_devices_name_all(self):
        """Test devices filter."""
        params = {"devices": ["r1", "r2"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_device_id_all(self):
        """Test device_id filter."""
        params = {"device_id": [self.devices[0].id, self.devices[1].id]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)


class SoftwareLCMFilterSetTestCase(TestCase):
    """Tests for SoftwareLCMFilterSet."""

    queryset = SoftwareLCM.objects.all()
    filterset = SoftwareLCMFilterSet

    def setUp(self):
        device_platforms = (
            Platform.objects.create(name="Cisco IOS", slug="cisco_ios"),
            Platform.objects.create(name="Arista EOS", slug="arista_eos"),
        )

        self.softwares = (
            SoftwareLCM.objects.create(
                device_platform=device_platforms[0],
                version="17.3.3 MD",
                alias="Amsterdam-17.3.3 MD",
                release_date="2019-01-10",
                end_of_support="2022-05-15",
                documentation_url="https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-15-4m-t/series.html",
                long_term_support=False,
                pre_release=True,
            ),
            SoftwareLCM.objects.create(
                device_platform=device_platforms[1],
                version="4.25M",
                alias="EOS 4.25M",
                release_date="2021-01-10",
                end_of_support="2026-05-13",
                documentation_url="https://www.arista.com/softdocs",
                long_term_support=True,
                pre_release=False,
            ),
        )

    def test_q_one_release_date(self):
        """Test q filter to find single record based on release_date."""
        params = {"q": "2021"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_q_one_eo_support(self):
        """Test q filter to find single record based on end_of_support."""
        params = {"q": "2022"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_q_one_version(self):
        """Test q filter to find single record based on version."""
        params = {"q": "4.25M"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_documentation_url(self):
        """Test documentation_url filter."""
        params = {"documentation_url": "https://www.arista.com/softdocs"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_long_term_support(self):
        """Test long_term_support filter."""
        params = {"long_term_support": True}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_pre_release(self):
        """Test pre_release filter."""
        params = {"pre_release": True}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)


class ValidatedSoftwareLCMFilterSetTestCase(TestCase):
    """Tests for ValidatedSoftwareLCMFilterSet."""

    queryset = ValidatedSoftwareLCM.objects.all()
    filterset = ValidatedSoftwareLCMFilterSet

    def setUp(self):
        device_platforms = (
            Platform.objects.create(name="Cisco IOS", slug="cisco_ios"),
            Platform.objects.create(name="Arista EOS", slug="arista_eos"),
        )

        self.softwares = (
            SoftwareLCM.objects.create(
                device_platform=device_platforms[0],
                version="17.3.3 MD",
                release_date="2019-01-10",
            ),
            SoftwareLCM.objects.create(
                device_platform=device_platforms[1],
                version="4.25M",
                release_date="2021-01-10",
            ),
        )

        manufacturer = Manufacturer.objects.create(name="Cisco", slug="cisco")
        device_type = DeviceType.objects.create(manufacturer=manufacturer, model="ASR-1000", slug="asr-1000")

        validated_software = ValidatedSoftwareLCM(
            software=self.softwares[0],
            start="2019-01-10",
            end="2023-05-14",
            preferred=True,
        )
        validated_software.device_types.set([device_type.pk])
        validated_software.save()

        validated_software = ValidatedSoftwareLCM(
            software=self.softwares[1],
            start="2020-04-15",
            end="2022-11-01",
            preferred=False,
        )
        validated_software.device_types.set([device_type.pk])
        validated_software.save()

    def test_q_one_start(self):
        """Test q filter to find single record based on start date."""
        params = {"q": "2019"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_q_one_end(self):
        """Test q filter to find single record based on end date."""
        params = {"q": "2022"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_software(self):
        """Test software filter."""
        params = {"software": [self.softwares[0].pk]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_preferred(self):
        """Test preferred filter."""
        params = {"preferred": True}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_valid(self):
        """Test valid filter."""
        date_valid_and_invalid = date(2019, 6, 11)
        date_two_valid = date(2021, 1, 4)
        date_two_invalid = date(2024, 1, 4)

        with time_machine.travel(date_valid_and_invalid):
            params = {"valid": True}
            self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)
            params = {"valid": False}
            self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

        with time_machine.travel(date_two_valid):
            params = {"valid": True}
            self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)
            params = {"valid": False}
            self.assertEqual(self.filterset(params, self.queryset).qs.count(), 0)

        with time_machine.travel(date_two_invalid):
            params = {"valid": True}
            self.assertEqual(self.filterset(params, self.queryset).qs.count(), 0)
            params = {"valid": False}
            self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)


class DeviceSoftwareValidationResultFilterSetTestCase(TestCase):
    """Tests for the DeviceSoftwareValidationResult model."""

    queryset = DeviceSoftwareValidationResult.objects.all()
    filterset = DeviceSoftwareValidationResultFilterSet

    def setUp(self):
        """Set up test objects."""
        self.device_1, self.device_2, self.device_3 = create_devices()
        self.platform = Platform.objects.all().first()
        self.software = SoftwareLCM.objects.create(
            device_platform=self.platform,
            version="17.3.3 MD",
            release_date="2019-01-10",
        )

        DeviceSoftwareValidationResult.objects.create(
            device=self.device_1,
            software=self.software,
            is_validated=True,
        )
        DeviceSoftwareValidationResult.objects.create(
            device=self.device_2,
            software=self.software,
            is_validated=False,
        )
        DeviceSoftwareValidationResult.objects.create(
            device=self.device_3,
            software=None,
            is_validated=False,
        )

    def test_devices_name_one(self):
        """Test devices filter."""
        params = {"device": ["sw1"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_devices_name_all(self):
        """Test devices filter."""
        params = {"device": ["sw1", "sw2", "sw3"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_device_type_slug(self):
        """Test device_type filter."""
        params = {"device_type": ["6509-E"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_device_roles_slug(self):
        """Test device_roles filter."""
        params = {"device_role": ["core-switch"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_device_type_id(self):
        """Test device_type_id filter."""
        device_type = DeviceType.objects.get(model="6509-E")
        params = {"device_type_id": [device_type.id]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_device_role_id(self):
        """Test device_role_id filter."""
        device_role = DeviceRole.objects.get(slug="core-switch")
        params = {"device_role_id": [device_role.id]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_device_id_all(self):
        """Test device_id filter."""
        params = {"device_id": [self.device_1.id, self.device_2.id, self.device_3.id]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_software(self):
        """Test software version filter."""
        params = {"software": ["17.3.3 MD"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_sw_missing(self):
        """Test sw_missing filter."""
        params = {"exclude_sw_missing": True}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)


class InventoryItemSoftwareValidationResultFilterSetTestCase(TestCase):
    """Tests for the DeviceSoftwareValidationResult model."""

    queryset = InventoryItemSoftwareValidationResult.objects.all()
    filterset = InventoryItemSoftwareValidationResultFilterSet

    def setUp(self):
        """Set up test objects."""
        self.inventory_items = create_inventory_items()
        self.platform = Platform.objects.all().first()
        self.software = SoftwareLCM.objects.create(
            device_platform=self.platform,
            version="17.3.3 MD",
            release_date="2019-01-10",
        )

        InventoryItemSoftwareValidationResult.objects.create(
            inventory_item=self.inventory_items[0],
            software=self.software,
            is_validated=True,
        )
        InventoryItemSoftwareValidationResult.objects.create(
            inventory_item=self.inventory_items[1],
            software=self.software,
            is_validated=False,
        )
        InventoryItemSoftwareValidationResult.objects.create(
            inventory_item=self.inventory_items[2],
            software=None,
            is_validated=False,
        )

    def test_inventory_item_name_one(self):
        """Test inventory items filter."""
        params = {"inventory_item": ["SUP2T Card"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_inventory_items_name_all(self):
        """Test devices filter."""
        params = {"inventory_item": ["SUP2T Card", "100GBASE-SR4 QSFP Transceiver", "48x RJ-45 Line Card"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_inventory_items_device_type_slug(self):
        """Test device_type filter."""
        params = {"device_type": ["6509-E"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_inventory_items_device_roles_slug(self):
        """Test device_roles filter."""
        params = {"device_role": ["core-switch"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_inventory_items_device_type_id(self):
        """Test device_type_id filter."""
        device_type = DeviceType.objects.get(model="6509-E")
        params = {"device_type_id": [device_type.id]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_inventory_items_device_role_id(self):
        """Test device_role_id filter."""
        device_role = DeviceRole.objects.get(slug="core-switch")
        params = {"device_role_id": [device_role.id]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_inventory_items_part_id(self):
        """Test device_type filter."""
        params = {"part_id": "WS-X6548-GE-TX"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_software(self):
        """Test software version filter."""
        params = {"software": ["17.3.3 MD"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_sw_missing(self):
        """Test sw_missing filter."""
        params = {"exclude_sw_missing": True}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)


class CVELCMTestCase(TestCase):
    """Tests for CVELCMFilter."""

    queryset = CVELCM.objects.all()
    filterset = CVELCMFilterSet

    def setUp(self):
        cve_ct = ContentType.objects.get_for_model(CVELCM)
        fixed = Status.objects.create(name="Fixed", slug="fixed", color="4caf50", description="Unit has been fixed")
        fixed.content_types.set([cve_ct])
        not_fixed = Status.objects.create(
            name="Not Fixed", slug="not-fixed", color="f44336", description="Unit is not fixed"
        )
        not_fixed.content_types.set([cve_ct])

        CVELCM.objects.create(
            name="CVE-2021-1391",
            published_date="2021-03-24",
            last_modified_date="2021-04-24",
            link="https://www.cvedetails.com/cve/CVE-2021-1391/",
            cvss=3,
            cvss_v2=3,
            cvss_v3=3,
        )
        CVELCM.objects.create(
            name="CVE-2021-44228",
            published_date="2021-12-10",
            last_modified_date="2022-04-24",
            link="https://www.cvedetails.com/cve/CVE-2021-44228/",
            status=not_fixed,
            cvss=5,
            cvss_v2=5,
            cvss_v3=5,
        )
        CVELCM.objects.create(
            name="CVE-2020-27134",
            published_date="2020-12-11",
            link="https://www.cvedetails.com/cve/CVE-2020-27134/",
            severity="Critical",
            status=fixed,
            cvss=7,
            cvss_v2=7,
            cvss_v3=7,
        )

    def test_q_one_year(self):
        """Test q filter to find single record based on year."""
        params = {"q": "2020"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_q_two_year(self):
        """Test q filter to find two records based on year."""
        params = {"q": "2021"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_q_link(self):
        """Test q filter to all records from link."""
        params = {"q": "cvedetails"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_status(self):
        """Test status filter."""
        params = {"status": ["fixed"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_exclude_status(self):
        """Test exclude_status filter."""
        params = {"exclude_status": ["fixed"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_severity(self):
        """Test severity filter."""
        params = {"severity": "Critical"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_published_date_before(self):
        """Test published_date_before filter."""
        params = {"published_date_before": "2021-01-01"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_published_date_after(self):
        """Test published_date_after filter."""
        params = {"published_date_after": "2021-01-01"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_last_modified_date_before(self):
        """Test last_modified_date_before filter."""
        params = {"last_modified_date_before": "2021-01-01"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 0)

    def test_last_modified_after(self):
        """Test last_modified_date_after filter."""
        params = {"last_modified_date_after": "2021-01-01"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_cvss_gte(self):
        """Test cvss__gte filter."""
        params = {"cvss__gte": 1}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)
        params = {"cvss__gte": 4}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)
        params = {"cvss__gte": 6}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)
        params = {"cvss__gte": 9}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 0)

    def test_cvss_lte(self):
        """Test cvss__lte filter."""
        params = {"cvss__lte": 1}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 0)
        params = {"cvss__lte": 4}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)
        params = {"cvss__lte": 6}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)
        params = {"cvss__lte": 9}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_cvss_v2_gte(self):
        """Test cvss_v2__gte filter."""
        params = {"cvss_v2__gte": 1}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)
        params = {"cvss_v2__gte": 4}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)
        params = {"cvss_v2__gte": 6}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)
        params = {"cvss_v2__gte": 9}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 0)

    def test_cvss_v2_lte(self):
        """Test cvss_v2__lte filter."""
        params = {"cvss_v2__lte": 1}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 0)
        params = {"cvss_v2__lte": 4}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)
        params = {"cvss_v2__lte": 6}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)
        params = {"cvss_v2__lte": 9}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_cvss_v3_gte(self):
        """Test cvss_v3__gte filter."""
        params = {"cvss_v3__gte": 1}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)
        params = {"cvss_v3__gte": 4}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)
        params = {"cvss_v3__gte": 6}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)
        params = {"cvss_v3__gte": 9}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 0)

    def test_cvss_v3_lte(self):
        """Test cvss_v3__lte filter."""
        params = {"cvss_v3__lte": 1}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 0)
        params = {"cvss_v3__lte": 4}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)
        params = {"cvss_v3__lte": 6}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)
        params = {"cvss_v3__lte": 9}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)


class VulnerabilityLCMTestCase(TestCase):
    """Tests for VulnerabilityLCMFilter."""

    queryset = VulnerabilityLCM.objects.all()
    filterset = VulnerabilityLCMFilterSet

    def setUp(self):
        inventory_items = create_inventory_items()
        cves = create_cves()
        softwares = create_softwares()
        vuln_ct = ContentType.objects.get_for_model(VulnerabilityLCM)
        fix_me = Status.objects.create(name="Fix Me", slug="fix_me", color="4caf50", description="Please fix me.")
        fix_me.content_types.set([vuln_ct])

        VulnerabilityLCM.objects.create(
            cve=cves[0],
            device=inventory_items[0].device,
            software=softwares[0],
        )
        VulnerabilityLCM.objects.create(
            cve=cves[1],
            device=inventory_items[1].device,
            software=softwares[1],
            status=fix_me,
        )
        VulnerabilityLCM.objects.create(
            cve=cves[2],
            inventory_item=inventory_items[2],
            software=softwares[2],
            status=fix_me,
        )

    def test_q_cve(self):
        """Test q filter to find single record based on CVE name."""
        params = {"q": "2020"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_q_device(self):
        """Test q filter to find single record based on Device name."""
        params = {"q": "sw1"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_q_inventory_item(self):
        """Test q filter to find single record based on Inventory Item name."""
        params = {"q": "48x RJ-45"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_q_software_device_platform(self):
        """Test q filter to find single record based on Software Device Platform name."""
        params = {"q": "Cisco IOS"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_q_software_version(self):
        """Test q filter to find single record based on Software version."""
        params = {"q": "4.22.9M"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)


class SoftwareImageLCMFilterSetTestCase(TestCase):
    """Tests for SoftwareImageLCMFilterSet."""

    queryset = SoftwareImageLCM.objects.all()
    filterset = SoftwareImageLCMFilterSet

    def setUp(self):
        manufacturer_cisco, _ = Manufacturer.objects.get_or_create(name="Cisco", slug="cisco")
        manufacturer_arista, _ = Manufacturer.objects.get_or_create(name="Arista", slug="arista")
        device_platform_cisco, _ = Platform.objects.get_or_create(
            name="Cisco IOS", slug="cisco_ios", manufacturer=manufacturer_cisco
        )
        device_platform_arista, _ = Platform.objects.get_or_create(
            name="Arista EOS", slug="arista_eos", manufacturer=manufacturer_arista
        )

        self.softwares = (
            SoftwareLCM.objects.create(
                device_platform=device_platform_cisco,
                version="17.3.3 MD",
                release_date="2019-01-10",
            ),
            SoftwareLCM.objects.create(
                device_platform=device_platform_arista,
                version="4.25M",
                release_date="2021-01-10",
            ),
        )

        devicetype_1, _ = DeviceType.objects.get_or_create(
            manufacturer=manufacturer_cisco, model="ASR-1000", slug="asr-1000"
        )
        self.devicetype_2, _ = DeviceType.objects.get_or_create(
            manufacturer=manufacturer_arista, model="7150S", slug="7150s"
        )

        soft_image = SoftwareImageLCM(
            image_file_name="ios17.3.3md.img",
            software=self.softwares[0],
            default_image=True,
        )
        soft_image.save()

        soft_image = SoftwareImageLCM(
            image_file_name="ios17.3.3md-ssl.img",
            software=self.softwares[0],
            default_image=False,
        )
        soft_image.device_types.set([devicetype_1.pk])
        soft_image.save()

        soft_image = SoftwareImageLCM(
            image_file_name="eos4.25.m.swi",
            software=self.softwares[1],
            default_image=True,
        )
        soft_image.device_types.set([self.devicetype_2.pk])
        soft_image.save()

    def test_q_image_name(self):
        """Test q filter to find single record based on the image name."""
        params = {"q": "ios17.3.3"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_q_soft_version(self):
        """Test q filter to find single record based on the software version."""
        params = {"q": "4.25M"}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)

    def test_software(self):
        """Test software filter."""
        params = {"software": [self.softwares[0].pk]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_default_image(self):
        """Test default_image filter."""
        params = {"default_image": True}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_device_types(self):
        """Test device_types filter."""
        params = {"device_types": [self.devicetype_2.model]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 1)
