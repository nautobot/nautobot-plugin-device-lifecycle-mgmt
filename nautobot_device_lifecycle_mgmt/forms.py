"""Forms implementation for the Lifecycle Management plugin."""
import logging
from django import forms
from django.db.models import Q

from nautobot.dcim.models import Device, DeviceRole, DeviceType, InventoryItem, Platform, Region, Site
from nautobot.extras.forms import (
    CustomFieldModelCSVForm,
    CustomFieldModelForm,
    CustomFieldFilterForm,
    CustomFieldBulkEditForm,
    RelationshipModelForm,
    StatusBulkEditFormMixin,
    StatusModelCSVFormMixin,
    StatusFilterFormMixin,
)
from nautobot.extras.models import Tag, Status
from nautobot.utilities.forms import (
    BootstrapMixin,
    BulkEditForm,
    DatePicker,
    DynamicModelChoiceField,
    DynamicModelMultipleChoiceField,
    StaticSelect2,
    BOOLEAN_WITH_BLANK_CHOICES,
    add_blank_choice,
    CSVModelChoiceField,
    TagFilterField,
)
from nautobot_device_lifecycle_mgmt.choices import (
    ContractTypeChoices,
    CurrencyChoices,
    PoCTypeChoices,
    CountryCodes,
    CVESeverityChoices,
)
from nautobot_device_lifecycle_mgmt.models import (
    HardwareLCM,
    InventoryItemSoftwareValidationResult,
    SoftwareLCM,
    ValidatedSoftwareLCM,
    DeviceSoftwareValidationResult,
    ContractLCM,
    ProviderLCM,
    ContactLCM,
    CVELCM,
    VulnerabilityLCM,
    SoftwareImageLCM,
)

logger = logging.getLogger("nautobot_device_lifecycle_mgmt")


class CSVMultipleModelChoiceField(forms.ModelMultipleChoiceField):
    """Reference a list of PKs."""

    def prepare_value(self, value):
        """Parse a comma-separated string of PKs into a list of PKs."""
        pk_list = []
        if isinstance(value, str):
            pk_list = [val.strip() for val in value.split(",") if val]

        return super().prepare_value(pk_list)


class HardwareLCMForm(BootstrapMixin, CustomFieldModelForm, RelationshipModelForm):
    """Hardware Device Lifecycle creation/edit form."""

    inventory_item = forms.ModelChoiceField(
        queryset=InventoryItem.objects.exclude(part_id__exact="")
        .distinct()
        .order_by("part_id")
        .values_list("part_id", flat=True),
        label="Inventory Part ID",
        to_field_name="part_id",
        required=False,
    )

    class Meta:
        """Meta attributes for the HardwareLCMForm class."""

        model = HardwareLCM
        fields = HardwareLCM.csv_headers

        widgets = {
            "release_date": DatePicker(),
            "end_of_sale": DatePicker(),
            "end_of_support": DatePicker(),
            "end_of_sw_releases": DatePicker(),
            "end_of_security_patches": DatePicker(),
        }


class HardwareLCMBulkEditForm(BootstrapMixin, BulkEditForm):
    """Hardware Device Lifecycle bulk edit form."""

    pk = forms.ModelMultipleChoiceField(queryset=HardwareLCM.objects.all(), widget=forms.MultipleHiddenInput)
    release_date = forms.DateField(widget=DatePicker(), required=False)
    end_of_sale = forms.DateField(widget=DatePicker(), required=False)
    end_of_support = forms.DateField(widget=DatePicker(), required=False)
    end_of_sw_releases = forms.DateField(widget=DatePicker(), required=False)
    end_of_security_patches = forms.DateField(widget=DatePicker(), required=False)
    documentation_url = forms.URLField(required=False)
    comments = forms.CharField(required=False)

    class Meta:
        """Meta attributes for the HardwareLCMBulkEditForm class."""

        nullable_fields = [
            "release_date",
            "end_of_sale",
            "end_of_support",
            "end_of_sw_releases",
            "end_of_security_patches",
            "documentation_url",
            "comments",
        ]


class HardwareLCMFilterForm(BootstrapMixin, forms.ModelForm):
    """Filter form to filter searches."""

    q = forms.CharField(
        required=False,
        label="Search",
        help_text="Select a date that will be used to search end_of_support and end_of_sale",
    )
    device_type = forms.ModelMultipleChoiceField(
        required=False, queryset=DeviceType.objects.all(), to_field_name="slug"
    )

    inventory_item = forms.ModelMultipleChoiceField(
        queryset=HardwareLCM.objects.exclude(inventory_item__isnull=True)
        .exclude(inventory_item__exact="")
        .values_list("inventory_item", flat=True),
        label="Inventory Part ID",
        required=False,
    )

    class Meta:
        """Meta attributes for the HardwareLCMFilterForm class."""

        model = HardwareLCM
        # Define the fields above for ordering and widget purposes
        fields = [
            "q",
            "device_type",
            "inventory_item",
            "end_of_sale",
            "end_of_support",
            "end_of_sw_releases",
            "end_of_security_patches",
            "documentation_url",
        ]

        widgets = {
            "end_of_sale": DatePicker(),
            "end_of_support": DatePicker(),
            "end_of_sw_releases": DatePicker(),
            "end_of_security_patches": DatePicker(),
        }


class HardwareLCMCSVForm(CustomFieldModelCSVForm):
    """Form for creating bulk Hardware Device Lifecycle notices."""

    device_type = forms.ModelChoiceField(
        required=False, queryset=DeviceType.objects.all(), to_field_name="model", label="Device type"
    )

    inventory_item = forms.ModelChoiceField(
        required=False,
        queryset=InventoryItem.objects.exclude(part_id__exact="")
        .distinct()
        .order_by("part_id")
        .values_list("part_id", flat=True),
        to_field_name="part_id",
        label="Inventory Item",
    )

    class Meta:
        """Meta attributes for the HardwareLCMCSVForm class."""

        model = HardwareLCM
        fields = HardwareLCM.csv_headers


class SoftwareLCMForm(BootstrapMixin, CustomFieldModelForm, RelationshipModelForm):
    """SoftwareLCM creation/edit form."""

    tags = DynamicModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)

    class Meta:
        """Meta attributes."""

        model = SoftwareLCM
        fields = (
            *SoftwareLCM.csv_headers,
            "tags",
        )

        widgets = {
            "release_date": DatePicker(),
            "end_of_support": DatePicker(),
        }


class SoftwareLCMFilterForm(BootstrapMixin, forms.ModelForm):
    """Filter form to filter searches for SoftwareLCM."""

    q = forms.CharField(
        required=False,
        label="Search",
        help_text="Search for version, alias, or date for release_date or end_of_support.",
    )
    version = forms.CharField(required=False)
    device_platform = forms.ModelMultipleChoiceField(
        required=False, queryset=Platform.objects.all(), to_field_name="slug"
    )
    release_date_before = forms.DateField(label="Release Date Before", required=False, widget=DatePicker())
    release_date_after = forms.DateField(label="Release Date After", required=False, widget=DatePicker())
    end_of_support_before = forms.DateField(label="End of Software Support Before", required=False, widget=DatePicker())
    end_of_support_after = forms.DateField(label="End of Software Support After", required=False, widget=DatePicker())

    class Meta:
        """Meta attributes."""

        model = SoftwareLCM
        fields = [
            "q",
            "version",
            "device_platform",
            "release_date_before",
            "release_date_after",
            "end_of_support_before",
            "end_of_support_after",
            "documentation_url",
            "long_term_support",
            "pre_release",
        ]

        widgets = {
            "long_term_support": StaticSelect2(choices=BOOLEAN_WITH_BLANK_CHOICES),
            "pre_release": StaticSelect2(choices=BOOLEAN_WITH_BLANK_CHOICES),
        }


class SoftwareLCMCSVForm(CustomFieldModelCSVForm):
    """Form for bulk creating SoftwareLCM objects."""

    device_platform = CSVModelChoiceField(
        queryset=Platform.objects.all(),
        required=True,
        to_field_name="slug",
        help_text="Device platform",
    )

    class Meta:
        """Meta attributes for the SoftwareLCMCSVForm class."""

        model = SoftwareLCM
        fields = SoftwareLCM.csv_headers


class SoftwareImageLCMForm(BootstrapMixin, CustomFieldModelForm, RelationshipModelForm):
    """SoftwareImageLCM creation/edit form."""

    software = DynamicModelChoiceField(queryset=SoftwareLCM.objects.all(), required=True)
    device_types = DynamicModelMultipleChoiceField(queryset=DeviceType.objects.all(), required=False)
    inventory_items = DynamicModelMultipleChoiceField(queryset=InventoryItem.objects.all(), required=False)
    object_tags = DynamicModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)

    tags = DynamicModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)

    class Meta:
        """Meta attributes."""

        model = SoftwareImageLCM
        fields = (
            *SoftwareImageLCM.csv_headers,
            "tags",
        )

    def clean(self):  # pylint: disable=too-many-locals,too-many-branches
        """Custom validation of the SoftwareImageLCMForm."""
        super().clean()
        device_types = self.cleaned_data.get("device_types")
        inventory_items = self.cleaned_data.get("inventory_items")
        object_tags = self.cleaned_data.get("object_tags")
        default_image = self.cleaned_data.get("default_image")
        software = self.cleaned_data.get("software")

        if software:
            software_images = SoftwareImageLCM.objects.filter(software=software)
            software_default_image = software_images.filter(default_image=True)
            if self.instance is not None and self.instance.pk is not None:
                software_images = software_images.filter(~Q(pk=self.instance.pk))
                software_default_image = software_default_image.filter(~Q(pk=self.instance.pk))

        if software and default_image and software_default_image.exists():
            msg = "Only one default Software Image is allowed for each Software."
            self.add_error("default_image", msg)

        assigned_objects_count = sum(obj.count() for obj in (device_types, inventory_items, object_tags))
        if default_image and assigned_objects_count > 0:
            msg = "Default image cannot be assigned to any objects."
            self.add_error("default_image", msg)
            if device_types.count() > 0:
                self.add_error("device_types", msg)
            if inventory_items.count() > 0:
                self.add_error("inventory_items", msg)
            if object_tags.count() > 0:
                self.add_error("object_tags", msg)

        if software and assigned_objects_count > 0:
            software_manufacturer = software.device_platform.manufacturer
            for device_type in device_types:
                if device_type.manufacturer != software_manufacturer:
                    msg = f"Manufacturer for {device_type.model} doesn't match the Software Platform Manufacturer."
                    self.add_error("device_types", msg)

                software_img_for_dt = software_images.filter(device_types__in=[device_type])
                if software_img_for_dt.exists():
                    msg = f"Device Type {device_type.model} already assigned to another Software Image."
                    self.add_error("device_types", msg)
                    self.add_error(None, msg)

            for object_tag in object_tags:
                software_img_for_tag = software_images.filter(object_tags__in=[object_tag])
                if software_img_for_tag.exists():
                    msg = f"Object Tag {object_tag.name} already assigned to another Software Image."
                    self.add_error("object_tags", msg)
                    self.add_error(None, msg)

            for inventory_item in inventory_items:
                software_img_for_invitem = software_images.filter(inventory_items__in=[inventory_item])
                if software_img_for_invitem.exists():
                    msg = f"Inventory Item {inventory_item.name} already assigned to another Software Image."
                    self.add_error("inventory_items", msg)
                    self.add_error(None, msg)


class SoftwareImageLCMFilterForm(BootstrapMixin, forms.ModelForm):
    """Filter form to filter searches for SoftwareImageLCM."""

    q = forms.CharField(
        required=False,
        label="Search",
        help_text="Search for image name or software version.",
    )
    software = DynamicModelMultipleChoiceField(required=False, queryset=SoftwareLCM.objects.all())
    image_file_name = forms.CharField(
        required=False,
        label="Image File name",
    )
    device_types = DynamicModelMultipleChoiceField(
        queryset=DeviceType.objects.all(),
        to_field_name="model",
        required=False,
    )
    inventory_items = DynamicModelMultipleChoiceField(
        queryset=InventoryItem.objects.all(),
        to_field_name="id",
        required=False,
    )
    object_tags = DynamicModelMultipleChoiceField(
        queryset=Tag.objects.all(),
        to_field_name="slug",
        required=False,
    )
    default_image = forms.BooleanField(required=False, widget=StaticSelect2(choices=BOOLEAN_WITH_BLANK_CHOICES))

    class Meta:
        """Meta attributes."""

        model = SoftwareImageLCM
        fields = [
            "q",
            "software",
            "image_file_name",
            "image_file_checksum",
            "download_url",
            "device_types",
            "inventory_items",
            "object_tags",
            "default_image",
        ]

        widgets = {
            "default_image": StaticSelect2(choices=BOOLEAN_WITH_BLANK_CHOICES),
        }


class SoftwareImageLCMCSVForm(CustomFieldModelCSVForm):
    """Form for bulk creating SoftwareImageLCM objects."""

    device_types = CSVMultipleModelChoiceField(
        queryset=DeviceType.objects.all(),
        required=False,
        to_field_name="model",
        help_text="Comma-separated list of DeviceType Models",
    )
    inventory_items = CSVMultipleModelChoiceField(
        queryset=InventoryItem.objects.all(),
        required=False,
        to_field_name="id",
        help_text="Comma-separated list of InventoryItem IDs",
    )
    object_tags = CSVMultipleModelChoiceField(
        queryset=Tag.objects.all(), required=False, to_field_name="slug", help_text="Comma-separated list of Tag Slugs"
    )

    class Meta:
        """Meta attributes for the SoftwareImageLCMCSVForm class."""

        model = SoftwareImageLCM
        fields = SoftwareImageLCM.csv_headers


class ValidatedSoftwareLCMForm(BootstrapMixin, CustomFieldModelForm, RelationshipModelForm):
    """ValidatedSoftwareLCM creation/edit form."""

    software = DynamicModelChoiceField(queryset=SoftwareLCM.objects.all(), required=True)
    devices = DynamicModelMultipleChoiceField(queryset=Device.objects.all(), required=False)
    device_types = DynamicModelMultipleChoiceField(queryset=DeviceType.objects.all(), required=False)
    device_roles = DynamicModelMultipleChoiceField(queryset=DeviceRole.objects.all(), required=False)
    inventory_items = DynamicModelMultipleChoiceField(queryset=InventoryItem.objects.all(), required=False)
    object_tags = DynamicModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)

    tags = DynamicModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)

    class Meta:
        """Meta attributes."""

        model = ValidatedSoftwareLCM
        fields = (
            "software",
            "devices",
            "device_types",
            "device_roles",
            "inventory_items",
            "object_tags",
            "start",
            "end",
            "preferred",
            "tags",
        )

        widgets = {
            "start": DatePicker(),
            "end": DatePicker(),
        }

    def clean(self):
        """Custom validation of the ValidatedSoftwareLCMForm."""
        super().clean()

        devices = self.cleaned_data.get("devices")
        device_types = self.cleaned_data.get("device_types")
        device_roles = self.cleaned_data.get("device_roles")
        inventory_items = self.cleaned_data.get("inventory_items")
        object_tags = self.cleaned_data.get("object_tags")

        if sum(obj.count() for obj in (devices, device_types, device_roles, inventory_items, object_tags)) == 0:
            msg = "You need to assign to at least one object."
            self.add_error(None, msg)


class ValidatedSoftwareLCMFilterForm(BootstrapMixin, CustomFieldModelForm, RelationshipModelForm):
    """Filter form to filter searches for SoftwareLCM."""

    q = forms.CharField(
        required=False,
        label="Search",
        help_text="Search for start or end date of validity.",
    )
    software = DynamicModelChoiceField(required=False, queryset=SoftwareLCM.objects.all())
    devices = DynamicModelMultipleChoiceField(
        queryset=Device.objects.all(),
        to_field_name="name",
        required=False,
    )
    device_types = DynamicModelMultipleChoiceField(
        queryset=DeviceType.objects.all(),
        to_field_name="model",
        required=False,
    )
    device_roles = DynamicModelMultipleChoiceField(
        queryset=DeviceRole.objects.all(),
        to_field_name="slug",
        required=False,
    )
    inventory_items = DynamicModelMultipleChoiceField(
        queryset=InventoryItem.objects.all(),
        to_field_name="name",
        required=False,
    )
    object_tags = DynamicModelMultipleChoiceField(
        queryset=Tag.objects.all(),
        to_field_name="slug",
        required=False,
    )
    start_before = forms.DateField(label="Valid Since Date Before", required=False, widget=DatePicker())
    start_after = forms.DateField(label="Valid Since Date After", required=False, widget=DatePicker())
    preferred = forms.BooleanField(required=False, widget=StaticSelect2(choices=BOOLEAN_WITH_BLANK_CHOICES))
    valid = forms.BooleanField(
        label="Valid Now", required=False, widget=StaticSelect2(choices=BOOLEAN_WITH_BLANK_CHOICES)
    )

    class Meta:
        """Meta attributes."""

        model = ValidatedSoftwareLCM
        fields = [
            "q",
            "software",
            "devices",
            "device_types",
            "device_roles",
            "inventory_items",
            "object_tags",
            "preferred",
            "valid",
            "start_before",
            "start_after",
        ]


class DeviceSoftwareValidationResultFilterForm(BootstrapMixin, CustomFieldModelForm, RelationshipModelForm):
    """Filter form to filter searches for DeviceSoftwareValidationResult."""

    q = forms.CharField(
        required=False,
        label="Search",
    )
    software = DynamicModelMultipleChoiceField(
        queryset=SoftwareLCM.objects.all(),
        to_field_name="version",
        required=False,
    )
    site = DynamicModelMultipleChoiceField(
        queryset=Site.objects.all(),
        to_field_name="slug",
        required=False,
    )
    region = DynamicModelMultipleChoiceField(
        queryset=Region.objects.all(),
        to_field_name="slug",
        required=False,
    )
    device = DynamicModelMultipleChoiceField(
        queryset=Device.objects.all(),
        to_field_name="name",
        required=False,
    )
    device_type = DynamicModelMultipleChoiceField(
        queryset=DeviceType.objects.all(),
        to_field_name="model",
        required=False,
    )
    device_role = DynamicModelMultipleChoiceField(
        queryset=DeviceRole.objects.all(),
        to_field_name="slug",
        required=False,
    )
    exclude_sw_missing = forms.BooleanField(
        required=False,
        widget=StaticSelect2(choices=BOOLEAN_WITH_BLANK_CHOICES),
        label="Exclude missing software",
    )

    class Meta:
        """Meta attributes."""

        model = DeviceSoftwareValidationResult
        fields = ["q", "software", "site", "region", "device", "device_type", "device_role", "exclude_sw_missing"]


class InventoryItemSoftwareValidationResultFilterForm(BootstrapMixin, CustomFieldModelForm, RelationshipModelForm):
    """Filter form to filter searches for InventoryItemSoftwareValidationResult."""

    q = forms.CharField(
        required=False,
        label="Search",
    )
    software = DynamicModelMultipleChoiceField(
        queryset=SoftwareLCM.objects.all(),
        to_field_name="version",
        required=False,
    )
    site = DynamicModelMultipleChoiceField(
        queryset=Site.objects.all(),
        to_field_name="slug",
        required=False,
    )
    region = DynamicModelMultipleChoiceField(
        queryset=Region.objects.all(),
        to_field_name="slug",
        required=False,
    )
    inventory_item = DynamicModelMultipleChoiceField(
        queryset=InventoryItem.objects.all(),
        to_field_name="name",
        required=False,
    )
    part_id = forms.CharField(
        required=False,
        label="Part ID",
    )
    device = DynamicModelMultipleChoiceField(
        queryset=Device.objects.all(),
        to_field_name="name",
        required=False,
    )
    device_type = DynamicModelMultipleChoiceField(
        queryset=DeviceType.objects.all(),
        to_field_name="model",
        required=False,
    )
    device_role = DynamicModelMultipleChoiceField(
        queryset=DeviceRole.objects.all(),
        to_field_name="slug",
        required=False,
    )
    exclude_sw_missing = forms.BooleanField(
        required=False,
        widget=StaticSelect2(choices=BOOLEAN_WITH_BLANK_CHOICES),
        label="Exclude missing software",
    )

    class Meta:
        """Meta attributes."""

        model = InventoryItemSoftwareValidationResult
        fields = [
            "q",
            "software",
            "site",
            "region",
            "inventory_item",
            "part_id",
            "device",
            "device_type",
            "device_role",
            "exclude_sw_missing",
        ]


class ValidatedSoftwareLCMCSVForm(CustomFieldModelCSVForm):
    """Form for bulk creating ValidatedSoftwareLCM objects."""

    devices = CSVMultipleModelChoiceField(
        queryset=Device.objects.all(),
        required=False,
        to_field_name="name",
        help_text="Comma-separated list of Device Names",
    )
    devices = CSVMultipleModelChoiceField(
        queryset=Device.objects.all(),
        required=False,
        to_field_name="name",
        help_text="Comma-separated list of Device Names",
    )
    device_types = CSVMultipleModelChoiceField(
        queryset=DeviceType.objects.all(),
        required=False,
        to_field_name="model",
        help_text="Comma-separated list of DeviceType Models",
    )
    device_roles = CSVMultipleModelChoiceField(
        queryset=DeviceRole.objects.all(),
        required=False,
        to_field_name="slug",
        help_text="Comma-separated list of DeviceRole Slugs",
    )
    inventory_items = CSVMultipleModelChoiceField(
        queryset=InventoryItem.objects.all(),
        required=False,
        to_field_name="name",
        help_text="Comma-separated list of InventoryItem Names",
    )
    object_tags = CSVMultipleModelChoiceField(
        queryset=Tag.objects.all(), required=False, to_field_name="slug", help_text="Comma-separated list of Tag Slugs"
    )

    class Meta:
        """Meta attributes for the ValidatedSoftwareLCM class."""

        model = ValidatedSoftwareLCM
        fields = ValidatedSoftwareLCM.csv_headers


class ContractLCMForm(BootstrapMixin, CustomFieldModelForm, RelationshipModelForm):
    """Device Lifecycle Contracts creation/edit form."""

    provider = forms.ModelChoiceField(
        queryset=ProviderLCM.objects.all(),
        label="Vendor",
        to_field_name="pk",
        required=True,
    )
    contract_type = forms.ChoiceField(choices=add_blank_choice(ContractTypeChoices.CHOICES), label="Contract Type")
    currency = forms.ChoiceField(
        required=False, widget=StaticSelect2, choices=add_blank_choice(CurrencyChoices.CHOICES)
    )
    tags = DynamicModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)

    class Meta:
        """Meta attributes for the ContractLCMForm class."""

        model = ContractLCM
        fields = [
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
            "tags",
        ]

        widgets = {
            "end": DatePicker(),
            "start": DatePicker(),
        }

    def get_form_kwargs(self):
        """Get from kwargs override to capture the query params sent from other pages withing the LCM project."""
        return {"provider": self.request.GET.get("provider")}  # pylint: disable=E1101


class ContractLCMBulkEditForm(BootstrapMixin, BulkEditForm):
    """Device Lifecycle Contrcts bulk edit form."""

    pk = forms.ModelMultipleChoiceField(queryset=ContractLCM.objects.all(), widget=forms.MultipleHiddenInput)
    provider = forms.ModelMultipleChoiceField(queryset=ProviderLCM.objects.all(), required=False)
    start = forms.DateField(widget=DatePicker(), required=False)
    end = forms.DateField(widget=DatePicker(), required=False)
    cost = forms.FloatField(required=False)
    currency = forms.ChoiceField(required=False, choices=CurrencyChoices.CHOICES)
    contract_type = forms.ChoiceField(choices=ContractTypeChoices.CHOICES, required=False)
    support_level = forms.CharField(required=False)

    class Meta:
        """Meta attributes for the ContractLCMBulkEditForm class."""

        nullable_fields = [
            "start",
            "end",
            "cost",
            "currency",
            "support_level",
            "contract_type",
        ]


class ContractLCMFilterForm(BootstrapMixin, forms.ModelForm):
    """Filter form to filter searches."""

    q = forms.CharField(required=False, label="Search")
    provider = forms.ModelMultipleChoiceField(required=False, queryset=ProviderLCM.objects.all(), to_field_name="pk")
    currency = forms.ChoiceField(required=False, widget=StaticSelect2, choices=CurrencyChoices.CHOICES)
    name = forms.CharField(required=False)

    class Meta:
        """Meta attributes for the ContractLCMFilterForm class."""

        model = ContractLCM
        # Define the fields above for ordering and widget purposes
        fields = [
            "q",
            "provider",
            "name",
            "start",
            "end",
            "cost",
            "currency",
            "support_level",
            "contract_type",
        ]

        widgets = {
            "start": DatePicker(),
            "end": DatePicker(),
        }


class ContractLCMCSVForm(CustomFieldModelCSVForm):
    """Form for creating bulk Device Lifecycle contracts."""

    provider = forms.ModelChoiceField(
        required=True, queryset=ProviderLCM.objects.all(), to_field_name="name", label="Contract Provider"
    )

    class Meta:
        """Meta attributes for the ContractLCMCSVForm class."""

        model = ContractLCM
        fields = ContractLCM.csv_headers


class ProviderLCMForm(BootstrapMixin, CustomFieldModelForm, RelationshipModelForm):
    """Device Lifecycle Contract Providers creation/edit form."""

    tags = DynamicModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)
    country = forms.ChoiceField(
        widget=StaticSelect2,
        required=False,
        choices=add_blank_choice(CountryCodes.CHOICES),
    )

    class Meta:
        """Meta attributes for the ProviderLCMForm class."""

        model = ProviderLCM
        fields = [
            "name",
            "description",
            "physical_address",
            "country",
            "phone",
            "email",
            "portal_url",
            "comments",
            "tags",
        ]


class ProviderLCMBulkEditForm(BootstrapMixin, BulkEditForm):
    """Device Lifecycle Contract Providers bulk edit form."""

    pk = forms.ModelMultipleChoiceField(queryset=ProviderLCM.objects.all(), widget=forms.MultipleHiddenInput)
    description = forms.CharField(required=False)
    physical_address = forms.CharField(required=False)
    contact_name = forms.CharField(required=False)
    contact_phone = forms.CharField(required=False)
    contact_email = forms.EmailField(required=False)
    comments = forms.CharField(required=False)

    class Meta:
        """Meta attributes for the ProviderLCMBulkEditForm class."""

        nullable_fields = [
            "description",
            "physical_address",
            "country",
            "contact_name",
            "contact_phone",
            "contact_email",
            "comments",
        ]


class ProviderLCMFilterForm(BootstrapMixin, forms.ModelForm):
    """Filter form to filter searches."""

    q = forms.CharField(required=False, label="Search")
    name = forms.CharField(required=False)
    country = forms.ChoiceField(
        widget=StaticSelect2,
        required=False,
        choices=add_blank_choice(CountryCodes.CHOICES),
    )

    class Meta:
        """Meta attributes for the ProviderLCMFilterForm class."""

        model = ProviderLCM
        # Define the fields above for ordering and widget purposes
        fields = [
            "q",
            "name",
            "description",
            "physical_address",
            "country",
            "phone",
            "email",
            "comments",
        ]


class ProviderLCMCSVForm(CustomFieldModelCSVForm):
    """Form for creating bulk Device Lifecycle providers."""

    class Meta:
        """Meta attributes for the ProviderLCMCSVForm class."""

        model = ProviderLCM
        fields = ProviderLCM.csv_headers


class ContactLCMForm(BootstrapMixin, CustomFieldModelForm, RelationshipModelForm):
    """Device Lifecycle Contract Resources creation/edit form."""

    type = forms.ChoiceField(choices=PoCTypeChoices.CHOICES, required=False)
    tags = DynamicModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)

    class Meta:
        """Meta attributes for the ContactLCMForm class."""

        model = ContactLCM
        fields = [
            "contract",
            "name",
            "address",
            "phone",
            "email",
            "comments",
            "type",
            "priority",
            "tags",
        ]

    def get_form_kwargs(self):
        """Get from kwargs override to capture the query params sent from other pages withing the LCM project."""
        return {
            "type": self.request.GET.get("type"),  # pylint: disable=E1101
            "contract": self.request.GET.get("contract"),  # pylint: disable=E1101
        }


class ContactLCMBulkEditForm(BootstrapMixin, BulkEditForm):
    """Device Lifecycle Contract Resources bulk edit form."""

    pk = forms.ModelMultipleChoiceField(queryset=ContractLCM.objects.all(), widget=forms.MultipleHiddenInput)
    address = forms.CharField(required=False)
    phone = forms.CharField(required=False)
    email = forms.EmailField(required=False)
    priority = forms.IntegerField(required=False)
    comments = forms.CharField(required=False)
    contract = forms.ModelChoiceField(queryset=ContractLCM.objects.all())

    class Meta:
        """Meta attributes for the ContactLCMBulkEditForm class."""

        nullable_fields = ["address", "phone", "email", "comments", "priority", "contract"]


class ContactLCMFilterForm(BootstrapMixin, forms.ModelForm):
    """Filter form to filter searches."""

    q = forms.CharField(required=False, label="Search")
    name = forms.CharField(required=False)
    contract = forms.ModelChoiceField(queryset=ContractLCM.objects.all(), required=False)
    priority = forms.IntegerField(required=False)

    class Meta:
        """Meta attributes for the ContactLCMFilterForm class."""

        model = ContactLCM
        # Define the fields above for ordering and widget purposes
        fields = [
            "q",
            "contract",
            "name",
            "address",
            "phone",
            "email",
            "priority",
        ]


class ContactLCMCSVForm(CustomFieldModelCSVForm):
    """Form for creating bulk Device Lifecycle resources/contacts."""

    contract = forms.ModelChoiceField(
        required=True, queryset=ContractLCM.objects.all(), to_field_name="name", label="Contract Name"
    )
    type = forms.ChoiceField(choices=PoCTypeChoices.CHOICES, label="PoC Type")

    class Meta:
        """Meta attributes for the ContactLCMCSVForm class."""

        model = ContactLCM
        fields = ContactLCM.csv_headers


class CVELCMForm(
    StatusBulkEditFormMixin, BootstrapMixin, CustomFieldModelForm, RelationshipModelForm
):  # pylint: disable=too-many-ancestors
    """CVE Lifecycle Management creation/edit form."""

    published_date = forms.DateField(widget=DatePicker())
    last_modified_date = forms.DateField(widget=DatePicker(), required=False)
    severity = forms.ChoiceField(choices=CVESeverityChoices.CHOICES, label="Severity", required=False)
    tags = DynamicModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)

    model = CVELCM

    class Meta:
        """Meta attributes for the CVELCMForm class."""

        model = CVELCM

        fields = [
            *CVELCM.csv_headers,
            "tags",
        ]

        widgets = {
            "published_date": DatePicker(),
            "last_modified_date": DatePicker(),
        }


class CVELCMBulkEditForm(StatusBulkEditFormMixin, BootstrapMixin, CustomFieldBulkEditForm):
    """CVE Lifecycle Management bulk edit form."""

    model = CVELCM
    pk = forms.ModelMultipleChoiceField(queryset=CVELCM.objects.all(), widget=forms.MultipleHiddenInput)
    description = forms.CharField(required=False)
    comments = forms.CharField(required=False)
    tags = DynamicModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)

    class Meta:
        """Meta attributes for the CVELCMBulkEditForm class."""

        nullable_fields = [
            "description",
            "comments",
            "status",
            "tags",
        ]


class CVELCMFilterForm(BootstrapMixin, StatusFilterFormMixin, CustomFieldFilterForm):
    """Filter form to filter searches for CVELCM."""

    model = CVELCM
    q = forms.CharField(
        required=False,
        label="Search",
        help_text="Search for name or link.",
    )
    severity = forms.ChoiceField(
        widget=StaticSelect2,
        required=False,
        choices=add_blank_choice(CVESeverityChoices.CHOICES),
    )

    published_date_before = forms.DateField(label="Published Date Before", required=False, widget=DatePicker())
    published_date_after = forms.DateField(label="Published Date After", required=False, widget=DatePicker())

    last_modified_date_before = forms.DateField(label="Last Modified Date Before", required=False, widget=DatePicker())
    last_modified_date_after = forms.DateField(label="Last Modified Date After", required=False, widget=DatePicker())

    cvss__gte = forms.FloatField(label="CVSS Score Above", required=False)
    cvss__lte = forms.FloatField(label="CVSS Score Below", required=False)

    cvss_v2__gte = forms.FloatField(label="CVSSv2 Score Above", required=False)
    cvss_v2__lte = forms.FloatField(label="CVSSv2 Score Below", required=False)

    cvss_v3__gte = forms.FloatField(label="CVSSv3 Score Above", required=False)
    cvss_v3__lte = forms.FloatField(label="CVSSv3 Score Below", required=False)

    status = DynamicModelMultipleChoiceField(queryset=Status.objects.all(), required=False, to_field_name="slug")
    exclude_status = DynamicModelMultipleChoiceField(
        label="Exclude Status",
        required=False,
        queryset=Status.objects.all(),
        query_params={"content_types": model._meta.label_lower},
        to_field_name="slug",
    )
    tag = TagFilterField(model)

    class Meta:
        """Meta attributes."""

        model = CVELCM
        fields = [
            "q",
            "published_date_before",
            "published_date_after",
            "last_modified_date_before",
            "last_modified_date_after",
            "severity",
            "status",
        ]


class CVELCMCSVForm(CustomFieldModelCSVForm, StatusModelCSVFormMixin):
    """Form for creating bulk CVEs."""

    severity = forms.ChoiceField(choices=CVESeverityChoices.CHOICES, label="CVE Severity")

    class Meta:
        """Meta attributes for the CVELCMCSVForm class."""

        model = CVELCM
        fields = CVELCM.csv_headers


class VulnerabilityLCMForm(
    StatusBulkEditFormMixin, BootstrapMixin, CustomFieldModelForm, RelationshipModelForm
):  # pylint: disable=too-many-ancestors
    """Vulnerability Lifecycle Management creation/edit form."""

    model = VulnerabilityLCM
    tags = DynamicModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)

    class Meta:
        """Meta attributes for the VulnerabilityLCMForm class."""

        model = VulnerabilityLCM

        fields = [
            "status",
            "tags",
        ]


class VulnerabilityLCMBulkEditForm(StatusBulkEditFormMixin, BootstrapMixin, CustomFieldBulkEditForm):
    """Vulnerability Lifecycle Management bulk edit form."""

    model = VulnerabilityLCM
    pk = forms.ModelMultipleChoiceField(queryset=VulnerabilityLCM.objects.all(), widget=forms.MultipleHiddenInput)
    tags = DynamicModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)

    class Meta:
        """Meta attributes for the VulnerabilityLCMBulkEditForm class."""

        nullable_fields = [
            "status",
            "tags",
        ]


class VulnerabilityLCMFilterForm(BootstrapMixin, StatusFilterFormMixin, CustomFieldFilterForm):
    """Filter form to filter searches for VulnerabilityLCM."""

    model = VulnerabilityLCM
    q = forms.CharField(
        required=False,
        label="Search",
        help_text="Search for name or link.",
    )
    cve = DynamicModelMultipleChoiceField(required=False, queryset=CVELCM.objects.all(), label="CVE")
    cve__published_date__lte = forms.DateField(label="CVE Published Date Before", required=False, widget=DatePicker())
    cve__published_date__gte = forms.DateField(label="CVE Published Date After", required=False, widget=DatePicker())
    cve__severity = forms.ChoiceField(
        label="CVE Severity",
        widget=StaticSelect2,
        required=False,
        choices=add_blank_choice(CVESeverityChoices.CHOICES),
    )
    software = DynamicModelMultipleChoiceField(required=False, queryset=SoftwareLCM.objects.all())
    device = DynamicModelMultipleChoiceField(required=False, queryset=Device.objects.all())
    inventory_item = DynamicModelMultipleChoiceField(required=False, queryset=InventoryItem.objects.all())
    status = DynamicModelMultipleChoiceField(queryset=Status.objects.all(), required=False, to_field_name="slug")
    exclude_status = DynamicModelMultipleChoiceField(
        label="Exclude Status",
        required=False,
        queryset=Status.objects.all(),
        query_params={"content_types": model._meta.label_lower},
        to_field_name="slug",
    )
    tag = TagFilterField(model)

    class Meta:
        """Meta attributes."""

        model = VulnerabilityLCM
        fields = [
            "q",
            *VulnerabilityLCM.csv_headers,
            "tags",
        ]
