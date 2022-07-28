"""Filters for Software Lifecycle QuerySets."""

from django.contrib.contenttypes.models import ContentType
from django.db.models import Case, IntegerField, Q, Value, When, Subquery

from nautobot.dcim.models import Device, InventoryItem
from nautobot.extras.models import RelationshipAssociation


class BaseSoftwareFilter:  # pylint: disable=too-few-public-methods
    """Base class for SoftwareFilter classes."""

    soft_obj_model = None
    soft_relation_name = None

    def __init__(self, qs, item_obj):
        """Initalize BaseSoftwareFilter."""
        self.software_qs = qs
        self.item_obj = item_obj

    def filter_qs(self):
        """Returns filtered SoftwareLCM query set."""
        soft_rel_sq = RelationshipAssociation.objects.filter(
            relationship__slug=self.soft_relation_name,
            destination_type=ContentType.objects.get_for_model(self.soft_obj_model),
            destination_id=self.item_obj.id,
        ).values("source_id")[:1]
        self.software_qs = self.software_qs.filter(id=Subquery(soft_rel_sq))

        return self.software_qs


class DeviceSoftwareFilter(BaseSoftwareFilter):  # pylint: disable=too-few-public-methods
    """Filter SoftwareLCM objects based on the Device object."""

    soft_obj_model = Device
    soft_relation_name = "device_soft"


class InventoryItemSoftwareFilter(BaseSoftwareFilter):  # pylint: disable=too-few-public-methods
    """Filter SoftwareLCM objects based on the Device object."""

    soft_obj_model = InventoryItem
    soft_relation_name = "inventory_item_soft"


class DeviceValidatedSoftwareFilter:  # pylint: disable=too-few-public-methods
    """Filter ValidatedSoftwareLCM objects based on the Device object."""

    def __init__(self, qs, item_obj):
        """Initalize DeviceValidatedSoftwareFilter."""
        self.validated_software_qs = qs
        self.item_obj = item_obj

    def filter_qs(self):
        """Returns filtered ValidatedSoftwareLCM query set."""
        self.validated_software_qs = self.validated_software_qs.filter(
            Q(devices=self.item_obj.pk)
            | Q(device_types=self.item_obj.device_type.pk, device_roles=self.item_obj.device_role.pk)
            | Q(device_types=self.item_obj.device_type.pk, device_roles=None)
            | Q(device_types=None, device_roles=self.item_obj.device_role.pk)
            | Q(object_tags__in=self.item_obj.tags.all())
        ).distinct()

        self.validated_software_qs = self._add_weights().order_by("weight", "start")

        return self.validated_software_qs

    def _add_weights(self):
        """Adds weights to allow ordering of the ValidatedSoftwareLCM assignments."""
        return self.validated_software_qs.annotate(
            weight=Case(
                When(devices=self.item_obj.pk, preferred=True, then=Value(10)),
                When(devices=self.item_obj.pk, preferred=False, then=Value(1000)),
                When(
                    device_types=self.item_obj.device_type.pk,
                    device_roles=self.item_obj.device_role.pk,
                    preferred=True,
                    then=Value(20),
                ),
                When(
                    device_types=self.item_obj.device_type.pk,
                    device_roles=self.item_obj.device_role.pk,
                    preferred=False,
                    then=Value(1010),
                ),
                When(device_types=self.item_obj.device_type.pk, device_roles=None, preferred=True, then=Value(30)),
                When(device_types=self.item_obj.device_type.pk, device_roles=None, preferred=False, then=Value(1030)),
                When(device_roles=self.item_obj.device_role.pk, preferred=True, then=Value(40)),
                When(device_roles=self.item_obj.device_role.pk, preferred=False, then=Value(1040)),
                When(preferred=True, then=Value(990)),
                default=Value(1990),
                output_field=IntegerField(),
            )
        )


class InventoryItemValidatedSoftwareFilter:  # pylint: disable=too-few-public-methods
    """Filter ValidatedSoftwareLCM objects based on the InventoryItem object."""

    def __init__(self, qs, item_obj):
        """Initalize InventoryItemValidatedSoftwareFilter."""
        self.validated_software_qs = qs
        self.item_obj = item_obj

    def filter_qs(self):
        """Returns filtered ValidatedSoftwareLCM query set."""
        validated_software_qs = self.validated_software_qs.filter(
            Q(inventory_items=self.item_obj.pk) | Q(object_tags__in=self.item_obj.tags.all())
        ).distinct()

        self.validated_software_qs = self._add_weights().order_by("weight", "start")

        return validated_software_qs

    def _add_weights(self):
        """Adds weights to allow ordering of the ValidatedSoftwareLCM assignments."""
        return self.validated_software_qs.annotate(
            weight=Case(
                When(devices=self.item_obj.pk, preferred=True, then=Value(10)),
                When(devices=self.item_obj.pk, preferred=False, then=Value(1000)),
                When(preferred=True, then=Value(20)),
                When(preferred=False, then=Value(1010)),
                default=Value(1990),
                output_field=IntegerField(),
            )
        )


class DeviceSoftwareImageFilter:  # pylint: disable=too-few-public-methods
    """Filter SoftwareImageLCM objects based on the Device object."""

    soft_obj_model = Device
    soft_relation_name = "device_soft"

    def __init__(self, qs, item_obj):
        """Initalize DeviceSoftwareImageLCMFilter."""
        self.softwareimage_qs = qs
        self.item_obj = item_obj

    def filter_qs(self):
        """Returns filtered SoftwareImageLCM query set."""
        soft_rel_obj = RelationshipAssociation.objects.filter(
            relationship__slug=self.soft_relation_name,
            destination_type=ContentType.objects.get_for_model(self.soft_obj_model),
            destination_id=self.item_obj.id,
        ).values("source_id")[:1]

        object_tag_q = Q(software=soft_rel_obj, object_tags__in=self.item_obj.tags.all())
        device_type_q = Q(software=soft_rel_obj, device_types=self.item_obj.device_type)
        default_image_q = Q(software=soft_rel_obj, default_image=True)

        device_soft_image_ot_qs = self.softwareimage_qs.filter(object_tag_q)
        if device_soft_image_ot_qs.exists():
            return device_soft_image_ot_qs

        device_soft_image_dt_qs = self.softwareimage_qs.filter(device_type_q)
        if device_soft_image_dt_qs.exists():
            return device_soft_image_dt_qs

        return self.softwareimage_qs.filter(default_image_q)


class InventoryItemSoftwareImageFilter:  # pylint: disable=too-few-public-methods
    """Filter SoftwareImageLCM objects based on the InventoryItem object."""

    soft_obj_model = InventoryItem
    soft_relation_name = "inventory_item_soft"

    def __init__(self, qs, item_obj):
        """Initalize InventoryItemSoftwareImageLCMFilter."""
        self.softwareimage_qs = qs
        self.item_obj = item_obj

    def filter_qs(self):
        """Returns filtered SoftwareImageLCM query set."""
        soft_rel_obj = RelationshipAssociation.objects.filter(
            relationship__slug=self.soft_relation_name,
            destination_type=ContentType.objects.get_for_model(self.soft_obj_model),
            destination_id=self.item_obj.id,
        ).values("source_id")[:1]

        object_tag_q = Q(software=soft_rel_obj, object_tags__in=self.item_obj.tags.all())
        inv_item_q = Q(software=soft_rel_obj, inventory_items=self.item_obj.pk)
        default_image_q = Q(software=soft_rel_obj, default_image=True)

        invitem_soft_image_ot_qs = self.softwareimage_qs.filter(object_tag_q)
        if invitem_soft_image_ot_qs.exists():
            return invitem_soft_image_ot_qs

        invitem_soft_image_dt_qs = self.softwareimage_qs.filter(inv_item_q)
        if invitem_soft_image_dt_qs.exists():
            return invitem_soft_image_dt_qs

        return self.softwareimage_qs.filter(default_image_q)


class DeviceTypeValidatedSoftwareFilter:  # pylint: disable=too-few-public-methods
    """Filter ValidatedSoftwareLCM objects based on the Device Type object."""

    def __init__(self, qs, item_obj):
        """Initalize DeviceTypeValidatedSoftwareFilter."""
        self.validated_software_qs = qs
        self.item_obj = item_obj

    def filter_qs(self):
        """Returns filtered ValidatedSoftwareLCM query set."""
        self.validated_software_qs = self.validated_software_qs.filter(
            Q(device_types=self.item_obj) | Q(device_types=None)
        ).distinct()

        self.validated_software_qs = self._add_weights().order_by("weight", "start")

        return self.validated_software_qs

    def _add_weights(self):
        """Adds weights to allow ordering of the ValidatedSoftwareLCM assignments."""
        return self.validated_software_qs.annotate(
            weight=Case(
                When(devices=self.item_obj.pk, preferred=True, then=Value(10)),
                When(devices=self.item_obj.pk, preferred=False, then=Value(1000)),
                When(
                    device_types=self.item_obj,
                    preferred=True,
                    then=Value(20),
                ),
                When(
                    device_types=self.item_obj,
                    preferred=False,
                    then=Value(1010),
                ),
                When(device_types=self.item_obj, preferred=True, then=Value(30)),
                When(device_types=self.item_obj, preferred=False, then=Value(1030)),
                When(preferred=True, then=Value(990)),
                default=Value(1990),
                output_field=IntegerField(),
            )
        )
