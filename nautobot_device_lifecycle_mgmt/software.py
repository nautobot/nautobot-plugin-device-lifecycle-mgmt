"""Django classes and functions handling Software Lifecycle related functionality."""

from django.contrib.contenttypes.models import ContentType
from nautobot.dcim.models import Device, InventoryItem, DeviceType
from nautobot.extras.models import RelationshipAssociation

from nautobot_device_lifecycle_mgmt.filters import ValidatedSoftwareLCMFilterSet
from nautobot_device_lifecycle_mgmt.models import ValidatedSoftwareLCM, SoftwareLCM
from nautobot_device_lifecycle_mgmt.tables import ValidatedSoftwareLCMTable


class ItemSoftware:
    """Base class providing functions for computing SoftwareLCM and ValidatedSoftwareLCM related objects."""

    soft_relation_name = None
    soft_obj_model = None

    def __init__(self, item_obj):
        """Initalize ItemSoftware object."""
        self.item_obj = item_obj
        self.validated_software_qs = ValidatedSoftwareLCM.objects.get_for_object(self.item_obj)

        if self.soft_relation_name:
            self.software = self.get_software()
        else:
            self.software = None

    def get_software(self):
        """Get software assigned to the object."""
        try:
            obj_soft_relation = RelationshipAssociation.objects.get(
                relationship__slug=self.soft_relation_name,
                destination_type=ContentType.objects.get_for_model(self.soft_obj_model),
                destination_id=self.item_obj.id,
            )
            obj_soft = SoftwareLCM.objects.get(id=obj_soft_relation.source_id)
        except (RelationshipAssociation.DoesNotExist, SoftwareLCM.DoesNotExist):
            obj_soft = None

        return obj_soft

    def get_validated_software_table(self):
        """Returns table of validated software linked to the object."""
        if not self.validated_software_qs:
            return None

        return ValidatedSoftwareLCMTable(
            list(self.validated_software_qs),
            orderable=False,
            exclude=(
                "software",
                "start",
                "actions",
            ),
        )

    def validate_software(self, preferred_only=False):
        """Validate software against the validated software objects."""
        if not (self.software and self.validated_software_qs.count()):
            return False

        validated_software_versions = ValidatedSoftwareLCMFilterSet(
            {"valid": True}, self.validated_software_qs.filter(software=self.software)
        ).qs
        if preferred_only:
            validated_software_versions = validated_software_versions.filter(preferred_only=True)

        return validated_software_versions.count() > 0


class DeviceSoftware(ItemSoftware):
    """Computes validated software objects for Device objects."""

    soft_obj_model = Device
    soft_relation_name = "device_soft"


class InventoryItemSoftware(ItemSoftware):
    """Computes validated software objects for InventoryItem objects."""

    soft_obj_model = InventoryItem
    soft_relation_name = "inventory_item_soft"


class DeviceTypeSoftware(ItemSoftware):
    """Computes validated software objects for Device Type objects."""

    soft_obj_model = DeviceType
    soft_relation_name = "device_type_soft"
