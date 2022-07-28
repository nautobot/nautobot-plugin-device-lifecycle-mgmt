"""Extended core templates for the Lifecycle Management plugin."""
from abc import ABCMeta

from django.db.models import Q

from nautobot.extras.plugins import PluginTemplateExtension
from nautobot.dcim.models import InventoryItem
from .models import HardwareLCM
from .software import (
    DeviceSoftware,
    InventoryItemSoftware,
    DeviceTypeSoftware,
)


class DeviceTypeHWLCM(PluginTemplateExtension, metaclass=ABCMeta):
    """Class to add table for HardwareLCM related to device type."""

    model = "dcim.devicetype"

    def right_page(self):
        """Display table on right side of page."""
        devtype_obj = self.context["object"]

        return self.render(
            "nautobot_device_lifecycle_mgmt/inc/general_notice.html",
            extra_context={"hw_notices": HardwareLCM.objects.filter(device_type=devtype_obj.pk)},
        )


class DeviceHWLCM(PluginTemplateExtension, metaclass=ABCMeta):
    """Class to add table for DeviceHWLCM related to device type."""

    model = "dcim.device"

    def right_page(self):
        """Display table on right side of page."""
        dev_obj = self.context["object"]

        return self.render(
            "nautobot_device_lifecycle_mgmt/inc/device_notice.html",
            extra_context={
                "hw_notices": HardwareLCM.objects.filter(
                    Q(device_type=dev_obj.device_type)
                    | Q(
                        inventory_item__in=[
                            i.part_id for i in InventoryItem.objects.filter(device__pk=dev_obj.pk) if i.part_id
                        ]
                    )
                )
            },
        )


class InventoryItemHWLCM(PluginTemplateExtension, metaclass=ABCMeta):
    """Class to add table for InventoryItemHWLCM related to inventory items."""

    model = "dcim.inventoryitem"

    def right_page(self):
        """Display table on right side of page."""
        inv_item_obj = self.context["object"]

        return self.render(
            "nautobot_device_lifecycle_mgmt/inc/general_notice.html",
            extra_context={"hw_notices": HardwareLCM.objects.filter(inventory_item=inv_item_obj.part_id)},
        )


class DeviceSoftwareLCMAndValidatedSoftwareLCM(
    PluginTemplateExtension,
):  # pylint: disable=abstract-method
    """Class to add table for SoftwareLCM and ValidatedSoftwareLCM related to device."""

    model = "dcim.device"

    def __init__(self, context):
        """Init setting up the DeviceSoftwareLCMAndValidatedSoftwareLCM object."""
        super().__init__(context)
        self.device_software = DeviceSoftware(item_obj=self.context["object"])

    def right_page(self):
        """Display table on right side of page."""
        extra_context = {
            "validsoft_table": self.device_software.get_validated_software_table(),
            "obj_soft": self.device_software.software,
            "obj_soft_valid": self.device_software.validate_software(),
        }

        return self.render(
            "nautobot_device_lifecycle_mgmt/inc/software_and_validatedsoftware_info.html",
            extra_context=extra_context,
        )


class InventoryItemSoftwareLCMAndValidatedSoftwareLCM(
    PluginTemplateExtension,
):  # pylint: disable=abstract-method
    """Class to add table for SoftwareLCM and ValidatedSoftwareLCM related to inventory item."""

    model = "dcim.inventoryitem"

    def __init__(self, context):
        """Init setting up the InventoryItemSoftwareLCMAndValidatedSoftwareLCM object."""
        super().__init__(context)
        self.inventory_item_software = InventoryItemSoftware(item_obj=self.context["object"])

    def right_page(self):
        """Display table on right side of page."""
        extra_context = {
            "validsoft_table": self.inventory_item_software.get_validated_software_table,
            "obj_soft": self.inventory_item_software.software,
            "obj_soft_valid": self.inventory_item_software.validate_software(),
        }

        return self.render(
            "nautobot_device_lifecycle_mgmt/inc/software_and_validatedsoftware_info.html",
            extra_context=extra_context,
        )


class DeviceTypeSoftwareLCMAndValidatedSoftwareLCM(
    PluginTemplateExtension,
):  # pylint: disable=abstract-method
    """Class to add table for SoftwareLCM and ValidatedSoftwareLCM related to device type."""

    model = "dcim.devicetype"

    def __init__(self, context):
        """Init setting up the DeviceTypeSoftwareLCMAndValidatedSoftwareLCM object."""
        super().__init__(context)
        self.device_type_software = DeviceTypeSoftware(item_obj=self.context["object"])

    def right_page(self):
        """Display table on right side of page."""
        extra_context = {
            "validsoft_table": self.device_type_software.get_validated_software_table(),
            "obj_soft_valid": self.device_type_software.validate_software(),
        }

        return self.render(
            "nautobot_device_lifecycle_mgmt/inc/software_and_validatedsoftware_info.html",
            extra_context=extra_context,
        )


template_extensions = [
    DeviceTypeHWLCM,
    DeviceHWLCM,
    InventoryItemHWLCM,
    DeviceSoftwareLCMAndValidatedSoftwareLCM,
    InventoryItemSoftwareLCMAndValidatedSoftwareLCM,
    DeviceTypeSoftwareLCMAndValidatedSoftwareLCM,
]
