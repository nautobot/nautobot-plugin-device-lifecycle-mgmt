"""Unit tests for views."""
import datetime

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse

from nautobot.utilities.testing import ViewTestCases
from nautobot.dcim.models import DeviceType, Manufacturer
from nautobot.users.models import ObjectPermission
from nautobot.extras.models import Status

from nautobot_device_lifecycle_mgmt.models import (
    HardwareLCM,
    DeviceSoftwareValidationResult,
    InventoryItemSoftwareValidationResult,
    CVELCM,
    VulnerabilityLCM,
    SoftwareImageLCM,
)
from .conftest import create_devices, create_inventory_items, create_cves, create_softwares

User = get_user_model()


class HardwareLCMViewTest(ViewTestCases.PrimaryObjectViewTestCase):  # pylint: disable=too-many-ancestors
    """Test the HardwareLCM views."""

    model = HardwareLCM
    bulk_edit_data = {"documentation_url": "https://cisco.com/eox"}

    def _get_base_url(self):
        return "plugins:{}:{}_{{}}".format(  # pylint: disable=consider-using-f-string
            self.model._meta.app_label, self.model._meta.model_name
        )

    @classmethod
    def setUpTestData(cls):
        """Create a superuser and token for API calls."""
        manufacturer = Manufacturer.objects.create(name="Cisco", slug="cisco")
        device_types = tuple(
            DeviceType.objects.create(model=model, slug=model, manufacturer=manufacturer)
            for model in ["c9300-24", "c9300-48", "c9500-24", "c9200-24", "c9200-48"]
        )

        HardwareLCM.objects.create(device_type=device_types[0], end_of_sale=datetime.date(2021, 4, 1))
        HardwareLCM.objects.create(device_type=device_types[1], end_of_sale=datetime.date(2021, 4, 1))

        cls.form_data = {
            "device_type": device_types[2].id,
            "end_of_sale": datetime.date(2021, 4, 1),
            "end_of_support": datetime.date(2024, 4, 1),
        }
        cls.csv_data = (
            "device_type,end_of_sale,end_of_support,end_of_sw_releases,end_of_security_patches,documentation_url",
            "c9500-24, 2021-10-06, 2022-10-06, 2025-10-06, 2026-10-06, https://cisco.com/eox",
            "c9200-24, 2022-10-06, 2023-10-06, 2025-10-06, 2026-10-06, https://cisco.com/eox",
            "c9200-48, 2023-10-06, 2024-10-06, 2025-10-06, 2026-10-06, https://cisco.com/eox",
        )

    def test_has_advanced_tab(self):
        pass


class ValidatedSoftwareDeviceReportViewTest(
    ViewTestCases.ListObjectsViewTestCase
):  # pylint: disable=too-many-ancestors
    """Test ValidatedSoftwareDeviceReportView"""

    model = DeviceSoftwareValidationResult

    def _get_base_url(self):
        return "plugins:nautobot_device_lifecycle_mgmt:validatedsoftware_device_report"

    @classmethod
    def setUpTestData(cls):
        """Set up test objects."""
        device_1, device_2, _ = create_devices()
        DeviceSoftwareValidationResult.objects.create(
            device=device_1,
            software=None,
            is_validated=False,
        )
        DeviceSoftwareValidationResult.objects.create(
            device=device_2,
            software=None,
            is_validated=False,
        )

    def test_validation_report_view_without_permission(self):
        """Test the SoftwareReportOverview."""

        self.assertHttpStatus(
            self.client.get(
                reverse(
                    "plugins:nautobot_device_lifecycle_mgmt:validatedsoftware_device_report",
                )
            ),
            403,
        )

    def test_validation_report_view_with_permission(self):
        """Test the SoftwareReportOverview."""
        obj_perm = ObjectPermission(name="Test permission", actions=["view"])
        obj_perm.save()
        obj_perm.users.add(self.user)
        obj_perm.object_types.add(ContentType.objects.get_for_model(self.model))
        self.assertHttpStatus(
            self.client.get(
                reverse(
                    "plugins:nautobot_device_lifecycle_mgmt:validatedsoftware_device_report",
                )
            ),
            200,
        )


class ValidatedSoftwareInventoryItemReportViewTest(
    ViewTestCases.ListObjectsViewTestCase
):  # pylint: disable=too-many-ancestors
    """Test ValidatedSoftwareInventoryItemReportView"""

    model = InventoryItemSoftwareValidationResult

    def _get_base_url(self):
        return "plugins:nautobot_device_lifecycle_mgmt:validatedsoftware_inventoryitem_report"

    @classmethod
    def setUpTestData(cls):
        """Set up test objects."""
        inventory_items = create_inventory_items()
        InventoryItemSoftwareValidationResult.objects.create(
            inventory_item=inventory_items[0],
            software=None,
            is_validated=False,
        )
        InventoryItemSoftwareValidationResult.objects.create(
            inventory_item=inventory_items[1],
            software=None,
            is_validated=False,
        )
        InventoryItemSoftwareValidationResult.objects.create(
            inventory_item=inventory_items[2],
            software=None,
            is_validated=False,
        )

    def test_validation_report_view_without_permission(self):
        """Test the SoftwareReportOverview."""

        self.assertHttpStatus(
            self.client.get(
                reverse(
                    "plugins:nautobot_device_lifecycle_mgmt:validatedsoftware_inventoryitem_report",
                )
            ),
            403,
        )

    def test_validation_report_view_with_permission(self):
        """Test the SoftwareReportOverview."""
        obj_perm = ObjectPermission(name="Test permission", actions=["view"])
        obj_perm.save()
        obj_perm.users.add(self.user)
        obj_perm.object_types.add(ContentType.objects.get_for_model(self.model))
        self.assertHttpStatus(
            self.client.get(
                reverse(
                    "plugins:nautobot_device_lifecycle_mgmt:validatedsoftware_inventoryitem_report",
                )
            ),
            200,
        )


class CVELCMViewTest(ViewTestCases.PrimaryObjectViewTestCase):  # pylint: disable=too-many-ancestors
    """Test the CVELCM views."""

    model = CVELCM
    bulk_edit_data = {"description": "Bulk edit views"}

    form_data = {
        "name": "Test 1",
        "slug": "test-1",
        "published_date": datetime.date(2022, 1, 1),
        "last_modified_date": datetime.date(2022, 2, 1),
        "link": "https://www.cvedetails.com/cve/CVE-2022-0001/",
    }

    @classmethod
    def setUpTestData(cls):
        CVELCM.objects.create(
            name="CVE-2021-1391", published_date="2021-03-24", last_modified_date="2021-03-25", link="https://www.cvedetails.com/cve/CVE-2021-1391/"
        )
        CVELCM.objects.create(
            name="CVE-2021-34699", published_date="2021-09-23", last_modified_date="2022-03-24", link="https://www.cvedetails.com/cve/CVE-2021-34699/"
        )

    def test_bulk_import_objects_with_constrained_permission(self):
        pass

    def test_bulk_import_objects_with_permission(self):
        pass

    def test_bulk_import_objects_without_permission(self):
        pass

    def test_has_advanced_tab(self):
        pass


class VulnerabilityLCMViewTest(ViewTestCases.PrimaryObjectViewTestCase):  # pylint: disable=too-many-ancestors
    """Test the VulnerabilityLCM views."""

    model = VulnerabilityLCM

    @classmethod
    def setUpTestData(cls):
        devices = create_devices()
        softwares = create_softwares()
        cves = create_cves()
        for i, cve in enumerate(cves):
            VulnerabilityLCM.objects.create(cve=cve, software=softwares[i], device=devices[i])

        vuln_ct = ContentType.objects.get_for_model(VulnerabilityLCM)
        status = Status.objects.create(name="Exempt", slug="exempt", color="4caf50", description="This unit is exempt.")
        status.content_types.set([vuln_ct])
        cls.bulk_edit_data = {"status": status.id}

    def test_bulk_import_objects_with_constrained_permission(self):
        pass

    def test_bulk_import_objects_with_permission(self):
        pass

    def test_bulk_import_objects_without_permission(self):
        pass

    # Disabling create view as these models are generated via Job.
    def test_create_object_with_constrained_permission(self):
        pass

    # Disabling create view as these models are generated via Job.
    def test_create_object_with_permission(self):
        pass

    # Disabling create view as these models are generated via Job.
    def test_create_object_without_permission(self):
        pass

    def test_has_advanced_tab(self):
        pass


class SoftwareImageLCMViewTest(ViewTestCases.PrimaryObjectViewTestCase):  # pylint: disable=too-many-ancestors
    """Test the SoftwareImageLCM views."""

    model = SoftwareImageLCM

    @classmethod
    def setUpTestData(cls):
        softwares = create_softwares()
        manufacturer = Manufacturer.objects.create(name="Cisco", slug="cisco")
        device_type = DeviceType.objects.create(manufacturer=manufacturer, model="6509-E", slug="6509-e")

        SoftwareImageLCM.objects.create(
            image_file_name="ios15.1.2m.img",
            software=softwares[0],
            download_url="ftp://images.local/cisco/ios15.1.2m.img",
            image_file_checksum="441rfabd75b0512r7fde7a7a66faa596",
            default_image=True,
        )
        softimage = SoftwareImageLCM.objects.create(
            image_file_name="ios4.22.9m.img",
            software=softwares[1],
            download_url="ftp://images.local/cisco/ios4.22.9m.img",
            image_file_checksum="58arfabd75b051fr7fde7a7ac6faa3fv",
            default_image=False,
        )
        softimage.device_types.set([device_type])

        cls.form_data = {
            "image_file_name": "eos_4.21m.swi",
            "software": softwares[-1].id,
            "download_url": "ftp://images.local/arista/eos_4.21m.swi",
            "image_file_checksum": "78arfabd75b0fa2vzas1e7a7ac6faa3fc",
            "default_image": True,
        }
        cls.csv_data = (
            "image_file_name,software",
            f"ios11.7.0m.img,{softwares[0].id}",
            f"ios16.3.1t.img,{softwares[0].id}",
            f"eos_4.21m.swi,{softwares[-1].id}",
        )

    def test_bulk_edit_objects_with_constrained_permission(self):
        pass

    def test_bulk_edit_objects_with_permission(self):
        pass

    def test_bulk_edit_objects_without_permission(self):
        pass

    def test_has_advanced_tab(self):
        pass
