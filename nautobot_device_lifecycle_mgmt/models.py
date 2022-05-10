"""Django models for the Lifecycle Management plugin."""

from datetime import datetime, date

from django.db import models
from django.urls import reverse
from django.core.exceptions import ValidationError
from django.conf import settings
from nautobot.extras.utils import extras_features
from nautobot.extras.models.statuses import StatusField
from nautobot.core.models.generics import PrimaryModel, OrganizationalModel
from nautobot.dcim.models import Device, InventoryItem
from nautobot.utilities.querysets import RestrictedQuerySet

from nautobot_device_lifecycle_mgmt import choices
from nautobot_device_lifecycle_mgmt.software_filters import (
    DeviceValidatedSoftwareFilter,
    InventoryItemValidatedSoftwareFilter,
    DeviceSoftwareFilter,
    InventoryItemSoftwareFilter,
    DeviceSoftwareImageFilter,
    InventoryItemSoftwareImageFilter,
)


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "webhooks",
)
class HardwareLCM(PrimaryModel):
    """HardwareLCM model for plugin."""

    # Set model columns
    device_type = models.ForeignKey(
        to="dcim.DeviceType",
        on_delete=models.CASCADE,
        verbose_name="Device Type",
        blank=True,
        null=True,
    )
    inventory_item = models.CharField(verbose_name="Inventory Item Part", max_length=255, blank=True, null=True)
    release_date = models.DateField(null=True, blank=True, verbose_name="Release Date")
    end_of_sale = models.DateField(null=True, blank=True, verbose_name="End of Sale")
    end_of_support = models.DateField(null=True, blank=True, verbose_name="End of Support")
    end_of_sw_releases = models.DateField(null=True, blank=True, verbose_name="End of Software Releases")
    end_of_security_patches = models.DateField(null=True, blank=True, verbose_name="End of Security Patches")
    documentation_url = models.URLField(blank=True, verbose_name="Documentation URL")
    comments = models.TextField(null=True, blank=True, verbose_name="Comments")

    csv_headers = [
        "device_type",
        "inventory_item",
        "release_date",
        "end_of_sale",
        "end_of_support",
        "end_of_sw_releases",
        "end_of_security_patches",
        "documentation_url",
        "comments",
    ]

    class Meta:
        """Meta attributes for the HardwareLCM class."""

        verbose_name = "Hardware Notice"
        ordering = ("end_of_support", "end_of_sale")
        constraints = [
            models.UniqueConstraint(fields=["device_type"], name="unique_device_type"),
            models.UniqueConstraint(fields=["inventory_item"], name="unique_inventory_item_part"),
            models.CheckConstraint(
                check=(
                    models.Q(inventory_item__isnull=True, device_type__isnull=False)
                    | models.Q(inventory_item__isnull=False, device_type__isnull=True)
                ),
                name="At least one of InventoryItem or DeviceType specified.",
            ),
            models.CheckConstraint(
                check=(models.Q(end_of_sale__isnull=False) | models.Q(end_of_support__isnull=False)),
                name="End of Sale or End of Support must be specified.",
            ),
        ]

    def __str__(self):
        """String representation of HardwareLCMs."""
        name = f"Device Type: {self.device_type}" if self.device_type else f"Inventory Part: {self.inventory_item}"
        if self.end_of_support:
            msg = f"{name} - End of support: {self.end_of_support}"
        else:
            msg = f"{name} - End of sale: {self.end_of_sale}"
        return msg

    def get_absolute_url(self):
        """Returns the Detail view for HardwareLCM models."""
        return reverse("plugins:nautobot_device_lifecycle_mgmt:hardwarelcm", kwargs={"pk": self.pk})

    @property
    def expired(self):
        """Return True or False if chosen field is expired."""
        expired_field = settings.PLUGINS_CONFIG["nautobot_device_lifecycle_mgmt"].get("expired_field", "end_of_support")

        # If the chosen or default field does not exist, default to one of the required fields that are present
        if not getattr(self, expired_field) and not getattr(self, "end_of_support"):
            expired_field = "end_of_sale"
        elif not getattr(self, expired_field) and not getattr(self, "end_of_sale"):
            expired_field = "end_of_support"

        today = datetime.today().date()
        return today >= getattr(self, expired_field)

    def save(self, *args, **kwargs):
        """Override save to assert a full clean."""
        # Full clean to assert custom validation in clean() for ORM, etc.
        super().full_clean()
        super().save(*args, **kwargs)

    def clean(self):
        """Override clean to do custom validation."""
        super().clean()

        if not any([self.inventory_item, self.device_type]) or all([self.inventory_item, self.device_type]):
            raise ValidationError(
                {
                    "inventory_item": "One and only one of `Inventory Item` OR `Device Type` must be specified.",
                    "device_type": "One and only one of `Inventory Item` OR `Device Type` must be specified.",
                }
            )

        if not self.end_of_sale and not self.end_of_support:
            raise ValidationError(
                {
                    "end_of_sale": "End of Sale or End of Support must be specified.",
                    "end_of_support": "End of Sale or End of Support must be specified.",
                }
            )

    def to_csv(self):
        """Return fields for bulk view."""
        return (
            self.device_type,
            self.inventory_item,
            self.release_date,
            self.end_of_sale,
            self.end_of_support,
            self.end_of_sw_releases,
            self.end_of_security_patches,
            self.documentation_url,
            self.comments,
        )


class SoftwareLCMQuerySet(RestrictedQuerySet):
    """Queryset for `SoftwareLCM` objects."""

    def get_for_object(self, obj):
        """Return all `SoftwareLCM` assigned to the given object."""
        if not isinstance(obj, models.Model):
            raise TypeError(f"{obj} is not an instance of Django Model class")
        if isinstance(obj, Device):
            qs = DeviceSoftwareFilter(qs=self, item_obj=obj).filter_qs()
        elif isinstance(obj, InventoryItem):
            qs = InventoryItemSoftwareFilter(qs=self, item_obj=obj).filter_qs()
        else:
            qs = self

        return qs


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "statuses",
    "webhooks",
)
class SoftwareLCM(PrimaryModel):
    """Software Life-Cycle Management model."""

    device_platform = models.ForeignKey(to="dcim.Platform", on_delete=models.CASCADE, verbose_name="Device Platform")
    version = models.CharField(max_length=50)
    alias = models.CharField(max_length=50, blank=True, null=True)
    release_date = models.DateField(null=True, blank=True, verbose_name="Release Date")
    end_of_support = models.DateField(null=True, blank=True, verbose_name="End of Software Support")
    documentation_url = models.URLField(blank=True, verbose_name="Documentation URL")
    long_term_support = models.BooleanField(verbose_name="Long Term Support", default=False)
    pre_release = models.BooleanField(verbose_name="Pre-Release", default=False)

    csv_headers = [
        "device_platform",
        "version",
        "alias",
        "release_date",
        "end_of_support",
        "documentation_url",
        "long_term_support",
        "pre_release",
    ]

    class Meta:
        """Meta attributes for SoftwareLCM."""

        verbose_name = "Software"
        ordering = ("device_platform", "version", "end_of_support", "release_date")
        unique_together = (
            "device_platform",
            "version",
        )

    def __str__(self):
        """String representation of SoftwareLCM."""
        return f"{self.device_platform} - {self.version}"

    def get_absolute_url(self):
        """Returns the Detail view for SoftwareLCM models."""
        return reverse("plugins:nautobot_device_lifecycle_mgmt:softwarelcm", kwargs={"pk": self.pk})

    def to_csv(self):
        """Return fields for bulk view."""
        return (
            self.device_platform.slug,
            self.version,
            self.alias,
            self.release_date,
            self.end_of_support,
            self.documentation_url,
            self.long_term_support,
            self.pre_release,
        )

    objects = SoftwareLCMQuerySet.as_manager()


class SoftwareImageLCMQuerySet(RestrictedQuerySet):
    """Queryset for `SoftwareImageLCM` objects."""

    def get_for_object(self, obj):
        """Return all `SoftwareImageLCM` assigned to the given object."""
        if not isinstance(obj, models.Model):
            raise TypeError(f"{obj} is not an instance of Django Model class")
        if isinstance(obj, Device):
            qs = DeviceSoftwareImageFilter(qs=self, item_obj=obj).filter_qs()
        elif isinstance(obj, InventoryItem):
            qs = InventoryItemSoftwareImageFilter(qs=self, item_obj=obj).filter_qs()
        else:
            qs = self

        return qs


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "statuses",
    "webhooks",
)
class SoftwareImageLCM(PrimaryModel):
    """SoftwareImageLCM model."""

    image_file_name = models.CharField(blank=False, max_length=100, verbose_name="Image File Name")
    software = models.ForeignKey(
        to="SoftwareLCM", on_delete=models.CASCADE, related_name="software_images", verbose_name="Software Version"
    )
    device_types = models.ManyToManyField(to="dcim.DeviceType", related_name="+", blank=True)
    inventory_items = models.ManyToManyField(to="dcim.InventoryItem", related_name="+", blank=True)
    object_tags = models.ManyToManyField(to="extras.Tag", related_name="+", blank=True)
    download_url = models.URLField(blank=True, verbose_name="Download URL")
    image_file_checksum = models.CharField(blank=True, max_length=256, verbose_name="Image File Checksum")
    default_image = models.BooleanField(verbose_name="Default Image", default=False)

    csv_headers = [
        "image_file_name",
        "software",
        "device_types",
        "inventory_items",
        "object_tags",
        "download_url",
        "image_file_checksum",
        "default_image",
    ]

    class Meta:
        """Meta attributes for SoftwareImageLCM."""

        verbose_name = "Software Image"
        ordering = ("software", "default_image", "image_file_name")
        unique_together = ("image_file_name", "software")

    def __str__(self):
        """String representation of SoftwareImageLCM."""
        msg = f"{self.image_file_name}"
        return msg

    def get_absolute_url(self):
        """Returns the Detail view for SoftwareImageLCM models."""
        return reverse("plugins:nautobot_device_lifecycle_mgmt:softwareimagelcm", kwargs={"pk": self.pk})

    def to_csv(self):
        """Return fields for bulk view."""
        return (
            self.image_file_name,
            self.software.id,
            f'"{",".join(str(device_type["model"]) for device_type in self.device_types.values())}"',
            f'"{",".join(str(inventory_item["id"]) for inventory_item in self.inventory_items.values())}"',
            f'"{",".join(str(object_tag["slug"]) for object_tag in self.object_tags.values())}"',
            self.download_url,
            self.image_file_checksum,
            self.default_image,
        )

    objects = SoftwareImageLCMQuerySet.as_manager()


class ValidatedSoftwareLCMQuerySet(RestrictedQuerySet):
    """Queryset for `ValidatedSoftwareLCM` objects."""

    def get_for_object(self, obj):
        """Return all `ValidatedSoftwareLCM` assigned to the given object."""
        if not isinstance(obj, models.Model):
            raise TypeError(f"{obj} is not an instance of Django Model class")
        if isinstance(obj, Device):
            qs = DeviceValidatedSoftwareFilter(qs=self, item_obj=obj).filter_qs()
        elif isinstance(obj, InventoryItem):
            qs = InventoryItemValidatedSoftwareFilter(qs=self, item_obj=obj).filter_qs()
        else:
            qs = self

        return qs


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "relationships",
    "statuses",
    "webhooks",
)
class ValidatedSoftwareLCM(PrimaryModel):
    """ValidatedSoftwareLCM model."""

    software = models.ForeignKey(to="SoftwareLCM", on_delete=models.CASCADE, verbose_name="Software Version")
    devices = models.ManyToManyField(to="dcim.Device", related_name="+", blank=True)
    device_types = models.ManyToManyField(to="dcim.DeviceType", related_name="+", blank=True)
    device_roles = models.ManyToManyField(to="dcim.DeviceRole", related_name="+", blank=True)
    inventory_items = models.ManyToManyField(to="dcim.InventoryItem", related_name="+", blank=True)
    object_tags = models.ManyToManyField(to="extras.Tag", related_name="+", blank=True)
    start = models.DateField(verbose_name="Valid Since")
    end = models.DateField(verbose_name="Valid Until", blank=True, null=True)
    preferred = models.BooleanField(verbose_name="Preferred Version", default=False)

    csv_headers = [
        "software",
        "devices",
        "device_types",
        "device_roles",
        "inventory_items",
        "object_tags",
        "start",
        "end",
        "preferred",
    ]

    class Meta:
        """Meta attributes for ValidatedSoftwareLCM."""

        verbose_name = "Validated Software"
        ordering = ("software", "preferred", "start")

    def __str__(self):
        """String representation of ValidatedSoftwareLCM."""
        msg = f"{self.software} - Valid since: {self.start}"
        return msg

    def get_absolute_url(self):
        """Returns the Detail view for ValidatedSoftwareLCM models."""
        return reverse("plugins:nautobot_device_lifecycle_mgmt:validatedsoftwarelcm", kwargs={"pk": self.pk})

    @property
    def valid(self):
        """Return True if software is currently valid, else return False."""
        today = date.today()
        if self.end:
            return self.end >= today > self.start

        return today > self.start

    def save(self, *args, **kwargs):
        """Override save to assert a full clean."""
        # Full clean to assert custom validation in clean() for ORM, etc.
        super().full_clean()
        super().save(*args, **kwargs)

    def clean(self):
        """Override clean to do custom validation."""
        super().clean()

        if (
            ValidatedSoftwareLCM.objects.filter(software=self.software, start=self.start, end=self.end)
            .exclude(pk=self.pk)
            .exists()
        ):
            raise ValidationError(
                "Validated Software object with this Software and Valid Since and Valid Until dates already exists."
            )

    def to_csv(self):
        """Return fields for bulk view."""
        return (
            self.software.id,
            f'"{",".join(str(device["name"]) for device in self.devices.values())}"',
            f'"{",".join(str(device_type["model"]) for device_type in self.device_types.values())}"',
            f'"{",".join(str(device_role["slug"]) for device_role in self.device_roles.values())}"',
            f'"{",".join(str(inventory_item["id"]) for inventory_item in self.inventory_items.values())}"',
            f'"{",".join(str(object_tag["slug"]) for object_tag in self.object_tags.values())}"',
            self.start,
            self.end,
            self.preferred,
        )

    objects = ValidatedSoftwareLCMQuerySet.as_manager()


@extras_features(
    "graphql",
)
class DeviceSoftwareValidationResult(PrimaryModel):
    """Device Software validation details model."""

    device = models.OneToOneField(
        to="dcim.Device",
        on_delete=models.CASCADE,
        help_text="The device",
        blank=False,
        related_name="device_software_validation",
    )
    software = models.ForeignKey(
        to="SoftwareLCM", on_delete=models.CASCADE, help_text="Device software", null=True, blank=True, related_name="+"
    )
    is_validated = models.BooleanField(null=True, blank=True)
    last_run = models.DateTimeField(null=True, blank=True)
    run_type = models.CharField(max_length=50, choices=choices.ReportRunTypeChoices)

    class Meta:
        """Meta attributes for DeviceSoftwareValidationResult."""

        verbose_name = "Device Software Validation Report"
        ordering = ("device",)

    def to_csv(self):
        """Indicates model fields to return as csv."""
        return (self.device.name, self.software.version, self.is_validated, self.last_run, self.run_type)


@extras_features(
    "graphql",
)
class InventoryItemSoftwareValidationResult(PrimaryModel):
    """InventoryItem Software validation details model."""

    inventory_item = models.OneToOneField(
        to="dcim.InventoryItem",
        on_delete=models.CASCADE,
        help_text="The Inventory Item",
        related_name="inventoryitem_software_validation",
    )
    software = models.ForeignKey(
        to="SoftwareLCM", on_delete=models.CASCADE, help_text="Inventory Item software", blank=True, null=True
    )
    is_validated = models.BooleanField(null=True, blank=True)
    last_run = models.DateTimeField(null=True, blank=True)
    run_type = models.CharField(max_length=50, choices=choices.ReportRunTypeChoices)

    class Meta:
        """Meta attributes for InventoryItemSoftwareValidationResult."""

        verbose_name = "Inventory Item Software Validation Report"
        ordering = ("inventory_item",)

    def to_csv(self):
        """Indicates model fields to return as csv."""
        return (self.inventory_item.name, self.software.version, self.is_validated, self.last_run, self.run_type)


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "webhooks",
)
class ContractLCM(PrimaryModel):
    """ContractLCM model for plugin."""

    # Set model columns
    provider = models.ForeignKey(
        to="nautobot_device_lifecycle_mgmt.ProviderLCM",
        on_delete=models.CASCADE,
        verbose_name="Vendor",
        blank=True,
        null=True,
    )
    name = models.CharField(max_length=100, unique=True)
    number = models.CharField(max_length=100, null=True, blank=True)
    start = models.DateField(null=True, blank=True, verbose_name="Contract Start Date")
    end = models.DateField(null=True, blank=True, verbose_name="Contract End Date")
    cost = models.DecimalField(null=True, blank=True, decimal_places=2, max_digits=15, verbose_name="Contract Cost")
    support_level = models.CharField(verbose_name="Support Level", max_length=64, blank=True, null=True)
    currency = models.CharField(verbose_name="Currency", max_length=4, blank=True, null=True)
    contract_type = models.CharField(null=True, blank=True, max_length=32, verbose_name="Contract Type")
    comments = models.TextField(blank=True)

    csv_headers = [
        "provider",
        "name",
        "number",
        "start",
        "end",
        "cost",
        "currency",
        "support_level",
        "contract_type",
        "comments",
    ]

    class Meta:
        """Meta attributes for the ContractLCM class."""

        verbose_name = "Contract"
        ordering = ("name", "start")

    def __str__(self):
        """String representation of ContractLCM."""
        return self.name

    def get_absolute_url(self):
        """Returns the Detail view for ContractLCM models."""
        return reverse("plugins:nautobot_device_lifecycle_mgmt:contractlcm", kwargs={"pk": self.pk})

    @property
    def expired(self):
        """Return True or False if chosen field is expired."""
        if not self.end:
            return False
        return datetime.today().date() >= self.end

    def save(self, *args, **kwargs):
        """Override save to assert a full clean."""
        # Full clean to assert custom validation in clean() for ORM, etc.
        super().full_clean()
        super().save(*args, **kwargs)

    def clean(self):
        """Override clean to do custom validation."""
        super().clean()

        if self.end and self.start:
            if self.end <= self.start:
                raise ValidationError("End date must be after the start date of the contract.")

    def to_csv(self):
        """Return fields for bulk view."""
        return (
            self.provider,
            self.name,
            self.number,
            self.start,
            self.end,
            self.cost,
            self.currency,
            self.support_level,
            self.contract_type,
            self.comments,
        )


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "webhooks",
)
class ProviderLCM(OrganizationalModel):
    """ProviderLCM model for plugin."""

    # Set model columns
    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=200, blank=True)
    physical_address = models.CharField(max_length=200, blank=True)
    country = models.CharField(max_length=3, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    email = models.EmailField(blank=True, verbose_name="E-mail")
    portal_url = models.URLField(blank=True, verbose_name="Portal URL")
    comments = models.TextField(blank=True)

    csv_headers = [
        "name",
        "description",
        "physical_address",
        "country",
        "phone",
        "email",
        "portal_url",
        "comments",
    ]

    class Meta:
        """Meta attributes for the class."""

        verbose_name = "Vendor"
        ordering = ("name",)

    def __str__(self):
        """String representation of ProviderLCM."""
        return self.name

    def get_absolute_url(self):
        """Returns the Detail view for ProviderLCM models."""
        return reverse("plugins:nautobot_device_lifecycle_mgmt:providerlcm", kwargs={"pk": self.pk})

    def save(self, *args, **kwargs):
        """Override save to assert a full clean."""
        # Full clean to assert custom validation in clean() for ORM, etc.
        super().full_clean()
        super().save(*args, **kwargs)

    def to_csv(self):
        """Return fields for bulk view."""
        return (
            self.name,
            self.description,
            self.physical_address,
            self.country,
            self.phone,
            self.email,
            self.portal_url,
            self.comments,
        )


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "webhooks",
)
class ContactLCM(PrimaryModel):
    """ContactLCM is a model representation of a contact used in Contracts."""

    name = models.CharField(max_length=80, null=True)
    address = models.CharField(max_length=200, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    email = models.EmailField(blank=True, verbose_name="Contact E-mail")
    comments = models.TextField(blank=True)
    priority = models.PositiveIntegerField(default=100)
    type = models.CharField(max_length=50, default=choices.PoCTypeChoices.UNASSIGNED)
    contract = models.ForeignKey(
        to="nautobot_device_lifecycle_mgmt.ContractLCM", on_delete=models.CASCADE, verbose_name="Contract", null=True
    )

    csv_headers = [
        "contract",
        "name",
        "address",
        "phone",
        "email",
        "comments",
        "type",
        "priority",
    ]

    class Meta:
        """Meta attributes for the class."""

        verbose_name = "Contract POC"

        unique_together = ("contract", "name")

        ordering = ("contract", "priority", "name")

    def get_absolute_url(self):
        """Returns the Detail view for ContactLCM models."""
        return reverse("plugins:nautobot_device_lifecycle_mgmt:contactlcm", kwargs={"pk": self.pk})

    def clean(self):
        """Override clean to do custom validation."""
        super().clean()
        if not any([self.phone, self.email]):
            raise ValidationError("Must specify at least one of phone or email for contact.")

        # Would to an exist() here, but we need to compare the pk in the event we are editing an
        # existing record.
        primary = ContactLCM.objects.filter(contract=self.contract, type=choices.PoCTypeChoices.PRIMARY).first()
        if primary:
            if self.pk != primary.pk and self.type == choices.PoCTypeChoices.PRIMARY:
                raise ValidationError(f"A primary contact already exist for contract {self.contract.name}.")

    def __str__(self):
        """String representation of the model."""
        return f"{self.name}"

    def to_csv(self):
        """Return fields for bulk view."""
        return (
            self.contract,
            self.name,
            self.address,
            self.phone,
            self.email,
            self.comments,
            self.type,
            self.priority,
        )


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "webhooks",
    "statuses",
)
class CVELCM(PrimaryModel):
    """CVELCM is a model representation of a cve vulnerability record."""

    name = models.CharField(max_length=16, blank=False, unique=True)
    published_date = models.DateField(verbose_name="Published Date")
    last_modified_date = models.DateField(
        null=True,
        blank=True,
        verbose_name="Last Modified Date"
        )
    link = models.URLField()
    status = StatusField(
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        to="extras.status",
    )
    description = models.CharField(max_length=255, blank=True, null=True)
    severity = models.CharField(max_length=50, default=choices.CVESeverityChoices.NONE)
    cvss = models.FloatField(blank=True, null=True, verbose_name="CVSS Base Score")
    cvss_v2 = models.FloatField(blank=True, null=True, verbose_name="CVSSv2 Score")
    cvss_v3 = models.FloatField(blank=True, null=True, verbose_name="CVSSv3 Score")
    fix = models.CharField(max_length=255, blank=True, null=True)
    comments = models.TextField(blank=True)

    csv_headers = [
        "name",
        "published_date",
        "last_modified_date",
        "link",
        "status",
        "description",
        "severity",
        "cvss",
        "cvss_v2",
        "cvss_v3",
        "fix",
        "comments",
    ]

    class Meta:
        """Meta attributes for the class."""

        verbose_name = "CVE"

        ordering = ("severity", "name")

    def get_absolute_url(self):
        """Returns the Detail view for CVELCM models."""
        return reverse("plugins:nautobot_device_lifecycle_mgmt:cvelcm", kwargs={"pk": self.pk})

    def __str__(self):
        """String representation of the model."""
        return f"{self.name}"

    def to_csv(self):
        """Return fields for bulk view."""
        return (
            self.name,
            self.published_date,
            self.last_modified_date,
            self.link,
            self.status,
            self.description,
            self.severity,
            self.cvss,
            self.cvss_v2,
            self.cvss_v3,
            self.fix,
            self.comments,
        )


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "webhooks",
    "statuses",
)
class VulnerabilityLCM(PrimaryModel):
    """VulnerabilityLCM is a model representation of vulnerability that affects a device."""

    cve = models.ForeignKey(CVELCM, on_delete=models.CASCADE, blank=True, null=True)
    software = models.ForeignKey(SoftwareLCM, on_delete=models.CASCADE, blank=True, null=True)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, blank=True, null=True)
    inventory_item = models.ForeignKey(InventoryItem, on_delete=models.CASCADE, blank=True, null=True)
    status = StatusField(
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        to="extras.status",
    )

    csv_headers = [
        "cve",
        "software",
        "device",
        "inventory_item",
        "status",
    ]

    class Meta:
        """Meta attributes for the class."""

        verbose_name = "Vulnerability"
        verbose_name_plural = "Vulnerabilities"

    def get_absolute_url(self):
        """Returns the Detail view for VulnerabilityLCM models."""
        return reverse("plugins:nautobot_device_lifecycle_mgmt:vulnerabilitylcm", kwargs={"pk": self.pk})

    def __str__(self):
        """String representation of the model."""
        name = f"Device: {self.device}" if self.device else f"Inventory Part: {self.inventory_item}"
        if self.software:
            name += f" - Software: {self.software}"
        if self.cve:
            name += f" - CVE: {self.cve}"
        return name

    def to_csv(self):
        """Return fields for bulk view."""
        return (
            self.cve,
            self.software,
            self.device,
            self.inventory_item,
            self.status,
        )
