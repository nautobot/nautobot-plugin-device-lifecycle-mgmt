"""Test forms."""
from django.test import TestCase
from django.contrib.contenttypes.models import ContentType

from nautobot.dcim.models import DeviceType, Manufacturer, Device, DeviceRole, Site, InventoryItem, Platform
from nautobot.extras.models import Status, Tag

from nautobot_device_lifecycle_mgmt.forms import (
    HardwareLCMForm,
    SoftwareLCMForm,
    ValidatedSoftwareLCMForm,
    CVELCMForm,
    SoftwareImageLCMForm,
)
from nautobot_device_lifecycle_mgmt.models import SoftwareImageLCM, SoftwareLCM, CVELCM


class HardwareLCMFormTest(TestCase):
    """Test class for Device Lifecycle forms."""

    def setUp(self):
        """Create necessary objects."""
        self.manufacturer = Manufacturer.objects.create(name="Cisco", slug="cisco")
        self.device_type = DeviceType.objects.create(model="c9300-24", slug="c9300-24", manufacturer=self.manufacturer)
        self.device_role = DeviceRole.objects.create(name="Backbone Switch", slug="backbone-switch")
        self.site = Site.objects.create(name="Test 1", slug="test-1")
        self.device = Device.objects.create(
            name="Test-9300-Switch",
            device_type=self.device_type,
            device_role=self.device_role,
            site=self.site,
        )
        self.inventory_item = InventoryItem.objects.create(
            device=self.device,
            manufacturer=self.manufacturer,
            name="SUP2T Card",
            part_id="VS-S2T-10G",
        )

    def test_specifying_all_fields(self):
        form = HardwareLCMForm(
            data={
                "device_type": self.device_type,
                "end_of_sale": "2021-04-01",
                "end_of_support": "2022-04-01",
                "end_of_sw_releases": "2023-04-01",
                "end_of_security_patches": "2024-04-01",
                "documentation_url": "https://cisco.com",
            }
        )
        self.assertTrue(form.is_valid())
        self.assertTrue(form.save())

    def test_one_of_eo_sale(self):
        form = HardwareLCMForm(data={"device_type": self.device_type, "end_of_sale": "2021-04-01"})
        self.assertTrue(form.is_valid())
        self.assertTrue(form.save())

    def test_one_of_eo_support(self):
        form = HardwareLCMForm(data={"device_type": self.device_type, "end_of_support": "2021-04-01"})
        self.assertTrue(form.is_valid())
        self.assertTrue(form.save())

    def test_required_fields_missing(self):
        form = HardwareLCMForm(
            data={
                "end_of_sale": "2021-04-01",
                "end_of_support": "2022-04-01",
                "end_of_sw_releases": "2023-04-01",
                "end_of_security_patches": "2024-04-01",
                "documentation_url": "https://cisco.com",
            }
        )
        self.assertFalse(form.is_valid())
        self.assertDictEqual(
            {
                "inventory_item": ["One and only one of `Inventory Item` OR `Device Type` must be specified."],
                "device_type": ["One and only one of `Inventory Item` OR `Device Type` must be specified."],
            },
            form.errors,
        )

    def test_eo_sale_support_fields_missing(self):
        form = HardwareLCMForm(data={"device_type": self.device_type})
        self.assertFalse(form.is_valid())
        self.assertIn("End of Sale or End of Support must be specified.", form.errors["end_of_sale"][0])

    def test_device_type_and_inventory_item_error(self):
        form = HardwareLCMForm(data={"device_type": self.device_type, "inventory_item": "VS-S2T-10G"})
        self.assertFalse(form.is_valid())
        self.assertIn(
            "One and only one of `Inventory Item` OR `Device Type` must be specified.", form.errors["inventory_item"][0]
        )

    def test_validation_error_end_of_sale(self):
        form = HardwareLCMForm(data={"device_type": self.device_type, "end_of_sale": "April 1st, 2021"})
        self.assertFalse(form.is_valid())
        self.assertIn("end_of_sale", form.errors)
        self.assertIn("Enter a valid date.", form.errors["end_of_sale"])

    def test_validation_error_end_of_support(self):
        form = HardwareLCMForm(
            data={"device_type": self.device_type, "end_of_sale": "2021-04-01", "end_of_support": "April 1st, 2022"}
        )
        self.assertFalse(form.is_valid())
        self.assertIn("end_of_support", form.errors)
        self.assertIn("Enter a valid date.", form.errors["end_of_support"])

    def test_validation_error_end_of_sw_releases(self):
        form = HardwareLCMForm(
            data={
                "device_type": self.device_type,
                "end_of_sale": "2021-04-01",
                "end_of_support": "2021-04-01",
                "end_of_sw_releases": "April 1st, 2022",
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("end_of_sw_releases", form.errors)
        self.assertIn("Enter a valid date.", form.errors["end_of_sw_releases"])

    def test_validation_error_end_of_security_patches(self):
        form = HardwareLCMForm(
            data={
                "device_type": self.device_type,
                "end_of_sale": "2021-04-01",
                "end_of_support": "2022-04-01",
                "end_of_sw_releases": "2023-04-01",
                "end_of_security_patches": "April 1st, 2022",
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("end_of_security_patches", form.errors)
        self.assertIn("Enter a valid date.", form.errors["end_of_security_patches"])

    def test_validation_error_documentation_url(self):
        form = HardwareLCMForm(
            data={
                "device_type": self.device_type,
                "end_of_sale": "2021-04-01",
                "end_of_support": "2022-04-01",
                "end_of_sw_releases": "2023-04-01",
                "end_of_security_patches": "2024-04-01",
                "documentation_url": "htttps://cisco.com",
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("documentation_url", form.errors)
        self.assertIn("Enter a valid URL.", form.errors["documentation_url"])


class SoftwareLCMFormTest(TestCase):  # pylint: disable=no-member
    """Test class for SoftwareLCM forms."""

    form_class = SoftwareLCMForm

    def setUp(self):
        """Create necessary objects."""
        self.device_platform = Platform.objects.create(name="Cisco IOS", slug="cisco_ios")

    def test_specifying_all_fields(self):
        data = {
            "device_platform": self.device_platform,
            "version": "17.3.3 MD",
            "alias": "Amsterdam-17.3.3 MD",
            "end_of_support": "2022-05-15",
            "documentation_url": "https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-15-4m-t/series.html",
            "long_term_support": True,
            "pre_release": False,
        }
        form = self.form_class(data)
        self.assertTrue(form.is_valid())
        self.assertTrue(form.save())

    def test_one_of_eo_support(self):
        data = {"device_platform": self.device_platform, "version": "17.3.3 MD", "end_of_support": "2022-05-15"}
        form = self.form_class(data)
        self.assertTrue(form.is_valid())
        self.assertTrue(form.save())

    def test_required_fields_missing(self):
        data = {
            "end_of_support": "2022-05-15",
            "documentation_url": "https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-15-4m-t/series.html",
        }
        form = self.form_class(data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(
            {"device_platform": ["This field is required."], "version": ["This field is required."]},
            form.errors,
        )

    def test_validation_error_end_of_support(self):
        data = {"device_platform": self.device_platform, "version": "17.3.3 MD", "end_of_support": "2022 May 5th"}
        form = self.form_class(data)
        self.assertFalse(form.is_valid())
        self.assertIn("end_of_support", form.errors)
        self.assertIn("Enter a valid date.", form.errors["end_of_support"])

    def test_validation_error_documentation_url(self):
        data = {
            "device_platform": self.device_platform,
            "version": "17.3.3 MD",
            "end_of_support": "2022-05-15",
            "documentation_url": "httpss://www.cisco.com/",
        }
        form = self.form_class(data)
        self.assertFalse(form.is_valid())
        self.assertIn("documentation_url", form.errors)
        self.assertIn("Enter a valid URL.", form.errors["documentation_url"])


class ValidatedSoftwareLCMFormTest(TestCase):  # pylint: disable=no-member
    """Test class for ValidatedSoftwareLCMForm forms."""

    form_class = ValidatedSoftwareLCMForm

    def setUp(self):
        """Create necessary objects."""
        device_platform = Platform.objects.create(name="Cisco IOS", slug="cisco_ios")
        self.software = SoftwareLCM.objects.create(
            **{
                "device_platform": device_platform,
                "version": "17.3.3 MD",
                "alias": "Amsterdam-17.3.3 MD",
                "end_of_support": "2022-05-15",
                "documentation_url": "https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-15-4m-t/series.html",
                "long_term_support": True,
                "pre_release": False,
            }
        )

        status_active = Status.objects.get(slug="active")
        manufacturer = Manufacturer.objects.create(name="Cisco", slug="cisco")
        site = Site.objects.create(name="Site 1", slug="site-1")
        devicerole = DeviceRole.objects.create(name="Router", slug="router", color="ff0000")
        self.devicetype_1 = DeviceType.objects.create(manufacturer=manufacturer, model="ASR-1000", slug="asr-1000")
        self.device_1 = Device.objects.create(
            device_type=self.devicetype_1, device_role=devicerole, name="Device 1", site=site, status=status_active
        )
        self.inventoryitem_1 = InventoryItem.objects.create(device=self.device_1, name="SwitchModule1")

    def test_specifying_all_fields_w_devices(self):
        data = {
            "software": self.software,
            "devices": [self.device_1],
            "start": "2021-06-06",
            "end": "2023-08-31",
            "preferred": False,
        }
        form = self.form_class(data)
        self.assertTrue(form.is_valid())
        self.assertTrue(form.save())

    def test_specifying_all_fields_w_device_type(self):
        data = {
            "software": self.software,
            "device_types": [self.devicetype_1],
            "start": "2021-06-06",
            "end": "2023-08-31",
            "preferred": False,
        }
        form = self.form_class(data)
        self.assertTrue(form.is_valid())
        self.assertTrue(form.save())

    def test_specifying_all_fields_w_inventory_item_type(self):
        data = {
            "software": self.software,
            "inventory_items": [self.inventoryitem_1],
            "start": "2021-06-06",
            "end": "2023-08-31",
            "preferred": False,
        }
        form = self.form_class(data)
        self.assertTrue(form.is_valid())
        self.assertTrue(form.save())

    def test_software_missing(self):
        data = {
            "end": "2023-08-31",
            "preferred": False,
        }
        form = self.form_class(data)
        with self.assertRaises(SoftwareLCM.DoesNotExist):
            form.is_valid()

    def test_validation_error_start(self):
        data = {
            "software": self.software,
            "devices": [self.device_1],
            "start": "2020 May 15th",
        }
        form = self.form_class(data)
        self.assertFalse(form.is_valid())
        self.assertIn("start", form.errors)
        self.assertIn("Enter a valid date.", form.errors["start"])

    def test_validation_error_end(self):
        data = {
            "software": self.software,
            "devices": [self.device_1],
            "start": "2021-06-06",
            "end": "2024 June 2nd",
        }
        form = self.form_class(data)
        self.assertFalse(form.is_valid())
        self.assertIn("end", form.errors)
        self.assertIn("Enter a valid date.", form.errors["end"])

    def test_assigned_to_must_specify_at_least_one_object(self):
        """ValidatedSoftwareLCM must be assigned to at least one object."""
        data = {
            "software": self.software,
            "start": "2021-06-06",
        }
        form = self.form_class(data)
        self.assertFalse(form.is_valid())
        self.assertEqual(
            "You need to assign to at least one object.",
            form.errors["__all__"][0],
        )


class CVELCMFormTest(TestCase):
    """Test class for Device Lifecycle forms."""

    def setUp(self):
        """Create necessary objects."""
        self.cve_ct = ContentType.objects.get_for_model(CVELCM)
        self.status = Status.objects.create(
            name="Fixed", slug="fixed", color="4caf50", description="Unit has been fixed"
        )
        self.status.content_types.set([self.cve_ct])

    def test_specifying_all_fields(self):
        form = CVELCMForm(
            data={
                "name": "CVE-2021-34699",
                "published_date": "2021-09-23",
                "last_modified_date": "2022-04-23",
                "link": "https://www.cvedetails.com/cve/CVE-2021-34699/",
                "status": self.status,
                "description": "Thanos",
                "severity": "High",
                "cvss": 6.8,
                "cvss_v2": 6.9,
                "cvss_v3": 6.7,
                "fix": "Avengers",
                "comments": "This is very bad juju.",
            }
        )
        self.assertTrue(form.is_valid())
        self.assertTrue(form.save())

    def test_required_fields_missing(self):
        form = CVELCMForm(data={"name": "CVE-2022-0002"})
        self.assertFalse(form.is_valid())
        self.assertDictEqual(
            {
                "published_date": ["This field is required."],
                "link": ["This field is required."],
            },
            form.errors,
        )


class SoftwareImageLCMFormTest(TestCase):  # pylint: disable=no-member,too-many-instance-attributes
    """Test class for SoftwareImageLCMForm forms."""

    form_class = SoftwareImageLCMForm

    def setUp(self):
        """Create necessary objects."""
        manufacturer_cisco, _ = Manufacturer.objects.get_or_create(name="Cisco", slug="cisco")
        manufacturer_arista, _ = Manufacturer.objects.get_or_create(name="Arista", slug="arista")
        device_platform, _ = Platform.objects.get_or_create(
            name="Cisco IOS", slug="cisco_ios", manufacturer=manufacturer_cisco
        )
        self.software_1 = SoftwareLCM.objects.create(
            **{
                "device_platform": device_platform,
                "version": "17.3.5 MD",
                "alias": "Amsterdam-17.3.5 MD",
                "end_of_support": "2022-05-15",
                "documentation_url": "https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-17.03/series.html",
                "long_term_support": True,
                "pre_release": False,
            }
        )
        self.software_2 = SoftwareLCM.objects.create(
            **{
                "device_platform": device_platform,
                "version": "17.3.6 MD",
                "alias": "Amsterdam-17.3.6 MD",
                "end_of_support": "2022-05-15",
                "documentation_url": "https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-17.03/series.html",
                "long_term_support": True,
                "pre_release": False,
            }
        )

        self.devicetype_1, _ = DeviceType.objects.get_or_create(
            manufacturer=manufacturer_cisco, model="ASR-1000", slug="asr-1000"
        )
        self.devicetype_2, _ = DeviceType.objects.get_or_create(
            manufacturer=manufacturer_arista, model="7150S", slug="7150s"
        )
        self.devicetype_3, _ = DeviceType.objects.get_or_create(
            manufacturer=manufacturer_cisco, model="7124", slug="7124"
        )
        self.tag_1, _ = Tag.objects.get_or_create(name="lcm", slug="lcm")
        self.tag_2, _ = Tag.objects.get_or_create(name="lcm2", slug="lcm2")
        status_active, _ = Status.objects.get_or_create(slug="active")
        site, _ = Site.objects.get_or_create(name="Site 1", slug="site-1")
        devicerole, _ = DeviceRole.objects.get_or_create(name="Router", slug="router", defaults={"color": "ff0000"})
        self.device_1, _ = Device.objects.get_or_create(
            device_type=self.devicetype_1, device_role=devicerole, name="Device 1", site=site, status=status_active
        )
        self.inventoryitem_1, _ = InventoryItem.objects.get_or_create(device=self.device_1, name="SwitchModule1")
        self.inventoryitem_2, _ = InventoryItem.objects.get_or_create(device=self.device_1, name="SwitchModule2")

        SoftwareImageLCM.objects.create(
            image_file_name="ios17.3.3Dmd.img",
            software=self.software_1,
            default_image=True,
        )

        soft_image = SoftwareImageLCM.objects.create(
            image_file_name="ios17.3.3dtmd.img",
            software=self.software_1,
            default_image=False,
        )
        soft_image.device_types.set([self.devicetype_3.pk])
        soft_image.inventory_items.set([self.inventoryitem_2.pk])
        soft_image.object_tags.set([self.tag_2.pk])
        soft_image.save()

    def test_specifying_all_fields_w_device_type(self):
        data = {
            "image_file_name": "ios17.3.3md.img",
            "software": self.software_1,
            "device_types": [self.devicetype_1],
            "download_url": "ftp://images.local/cisco/ios17.3.3md.img",
            "image_file_checksum": "441rfabd75b0512r7fde7a7a66faa596",
            "default_image": False,
        }
        form = self.form_class(data)
        self.assertTrue(form.is_valid())
        self.assertTrue(form.save())

    def test_specifying_all_fields_w_inventory_item(self):
        data = {
            "image_file_name": "ios17.3.3md.img",
            "software": self.software_1,
            "inventory_items": [self.inventoryitem_1],
            "download_url": "ftp://images.local/cisco/ios17.3.3md.img",
            "image_file_checksum": "441rfabd75b0512r7fde7a7a66faa596",
            "default_image": False,
        }
        form = self.form_class(data)
        self.assertTrue(form.is_valid())
        self.assertTrue(form.save())

    def test_specifying_all_fields_w_object_tag(self):
        data = {
            "image_file_name": "ios17.3.3md.img",
            "software": self.software_1,
            "object_tags": [self.tag_1],
            "download_url": "ftp://images.local/cisco/ios17.3.3md.img",
            "image_file_checksum": "441rfabd75b0512r7fde7a7a66faa596",
            "default_image": False,
        }
        form = self.form_class(data)
        self.assertTrue(form.is_valid())
        self.assertTrue(form.save())

    def test_software_missing(self):
        data = {
            "image_file_name": "ios17.3.3md.img",
        }
        form = self.form_class(data)
        form.is_valid()
        self.assertIn("software", form.errors)
        self.assertIn(
            "This field is required.",
            form.errors["software"],
        )

    def test_at_most_one_default_image_per_software(self):
        data = {
            "image_file_name": "ios17.3.3md.img",
            "software": self.software_1,
            "default_image": True,
        }
        form = self.form_class(data)
        self.assertFalse(form.is_valid())
        self.assertIn("default_image", form.errors)
        self.assertIn(
            "Only one default Software Image is allowed for each Software.",
            form.errors["default_image"],
        )

    def test_default_image_cannot_have_assignments(self):
        data = {
            "image_file_name": "ios17.3.3md.img",
            "software": self.software_2,
            "device_types": [self.devicetype_2],
            "default_image": True,
        }
        form = self.form_class(data)
        self.assertFalse(form.is_valid())
        self.assertIn("device_types", form.errors)
        self.assertIn("default_image", form.errors)
        self.assertIn(
            "Default image cannot be assigned to any objects.",
            form.errors["device_types"][0],
        )
        self.assertIn(
            "Default image cannot be assigned to any objects.",
            form.errors["default_image"][0],
        )

    def test_image_assigned_only_one_device_type_per_software(self):
        data = {
            "image_file_name": "ios17.3.3dt3md.img",
            "software": self.software_1,
            "device_types": [self.devicetype_3],
            "default_image": False,
        }
        form = self.form_class(data)
        self.assertFalse(form.is_valid())
        self.assertIn("device_types", form.errors)
        self.assertRegex(
            form.errors["device_types"][0], r"Device Type .+? already assigned to another Software Image\."
        )

    def test_image_assigned_only_one_object_tag_per_software(self):
        data = {
            "image_file_name": "ios17.3.3dt3md.img",
            "software": self.software_1,
            "object_tags": [self.tag_2],
            "default_image": False,
        }
        form = self.form_class(data)
        self.assertFalse(form.is_valid())
        self.assertIn("object_tags", form.errors)
        self.assertRegex(form.errors["object_tags"][0], r"Object Tag .+? already assigned to another Software Image\.")

    def test_image_assigned_only_one_inventory_item_per_software(self):
        data = {
            "image_file_name": "ios17.3.3dt3md.img",
            "software": self.software_1,
            "inventory_items": [self.inventoryitem_2],
            "default_image": False,
        }
        form = self.form_class(data)
        self.assertFalse(form.is_valid())
        self.assertIn("inventory_items", form.errors)
        self.assertRegex(
            form.errors["inventory_items"][0], r"Inventory Item .+? already assigned to another Software Image\."
        )

    def test_soft_manuf_must_match_platform_manuf(self):
        data = {
            "image_file_name": "ios17.3.3md.img",
            "software": self.software_1,
            "device_types": [self.devicetype_2],
            "default_image": False,
        }
        form = self.form_class(data)
        self.assertFalse(form.is_valid())
        self.assertIn("device_types", form.errors)
        self.assertIn(
            "doesn't match the Software Platform Manufacturer.",
            form.errors["device_types"][0],
        )

    def test_validation_error_download_url(self):
        data = {
            "image_file_name": "ios17.3.3md.img",
            "software": self.software_1,
            "device_types": [self.devicetype_2],
            "default_image": False,
            "download_url": "ftppp://images.local.my.org/",
        }
        form = self.form_class(data)
        self.assertFalse(form.is_valid())
        self.assertIn("download_url", form.errors)
        self.assertIn("Enter a valid URL.", form.errors["download_url"])
