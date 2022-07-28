"""Tables implementation for the Lifecycle Management plugin."""

from django.urls import reverse
from django.utils.safestring import mark_safe
import django_tables2 as tables
from django_tables2.utils import A
from nautobot.utilities.tables import (
    BaseTable,
    ButtonsColumn,
    BooleanColumn,
    LinkedCountColumn,
    TagColumn,
    ToggleColumn,
)
from nautobot.extras.tables import StatusTableMixin
from nautobot_device_lifecycle_mgmt.models import (
    HardwareLCM,
    SoftwareLCM,
    ValidatedSoftwareLCM,
    ContractLCM,
    ProviderLCM,
    ContactLCM,
    CVELCM,
    VulnerabilityLCM,
    DeviceSoftwareValidationResult,
    InventoryItemSoftwareValidationResult,
    SoftwareImageLCM,
)


class M2MLinkedCountColumn(LinkedCountColumn):
    """Linked count column supporting many-to-many fields."""

    def render(self, record, value):
        """Render the resulting URL."""
        if value:
            url = reverse(self.viewname, kwargs=self.view_kwargs)
            if self.url_params:
                url += "?"
                for key, kval in self.url_params.items():
                    if isinstance(kval, tuple):
                        values = getattr(record, kval[0]).values(kval[1])
                        url += "&".join([f"{key}={val[key]}" for val in values])
                    else:
                        url += f"&{key}={getattr(record, kval)}"
            return mark_safe(f'<a href="{url}">{value}</a>')  # nosec
        return value


class PercentageColumn(tables.Column):
    """Column used to display percentage."""

    def render(self, value):
        """Render percentage value."""
        return f"{value} %"


class HardwareLCMTable(BaseTable):
    """Table for list view."""

    pk = ToggleColumn()
    name = tables.LinkColumn(
        "plugins:nautobot_device_lifecycle_mgmt:hardwarelcm", text=lambda record: record, args=[A("pk")]
    )
    reference_item = tables.TemplateColumn(
        template_code="""{% if record.device_type %}
                    <a href="{% url 'dcim:devicetype' pk=record.device_type.pk %}">{{ record.device_type }}</a>
                    {% elif record.inventory_item %}
                    {{ record.inventory_item }}
                    {% endif %}""",
        verbose_name="Reference",
    )
    documentation_url = tables.TemplateColumn(
        template_code="""{% if record.documentation_url %}
                    <a href="{{ record.documentation_url }}" target="_blank" data-toggle="tooltip" data-placement="left" title="{{ record.documentation_url }}">
                        <span class="mdi mdi-open-in-new"></span>
                    </a>
                    {% else %}
                    —
                    {% endif %}""",
        verbose_name="Documentation",
    )
    actions = ButtonsColumn(HardwareLCM, buttons=("changelog", "edit", "delete"))

    class Meta(BaseTable.Meta):  # pylint: disable=too-few-public-methods
        """Meta attributes."""

        model = HardwareLCM
        fields = (
            "pk",
            "name",
            "reference_item",
            "release_date",
            "end_of_sale",
            "end_of_support",
            "end_of_sw_releases",
            "end_of_security_patches",
            "documentation_url",
            "actions",
        )


class SoftwareLCMTable(BaseTable):
    """Table for SoftwareLCMListView."""

    pk = ToggleColumn()
    name = tables.LinkColumn(
        "plugins:nautobot_device_lifecycle_mgmt:softwarelcm",
        text=lambda record: record,
        args=[A("pk")],
        orderable=False,
    )
    device_platform = tables.TemplateColumn("{{ record.device_platform }}")
    long_term_support = BooleanColumn()
    pre_release = BooleanColumn()
    actions = ButtonsColumn(SoftwareLCM, buttons=("edit", "delete"))

    class Meta(BaseTable.Meta):  # pylint: disable=too-few-public-methods
        """Meta attributes."""

        model = SoftwareLCM
        fields = (
            "pk",
            "name",
            "version",
            "alias",
            "device_platform",
            "release_date",
            "end_of_support",
            "long_term_support",
            "pre_release",
            "actions",
        )


class SoftwareImageLCMTable(BaseTable):
    """Table for SoftwareImageLCM."""

    pk = ToggleColumn()
    name = tables.LinkColumn(
        "plugins:nautobot_device_lifecycle_mgmt:softwareimagelcm",
        text=lambda record: record,
        args=[A("pk")],
        orderable=False,
    )
    software = tables.LinkColumn(verbose_name="Software")
    device_type_count = M2MLinkedCountColumn(
        viewname="dcim:devicetype_list", url_params={"model": ("device_types", "model")}, verbose_name="Device Types"
    )
    object_tag_count = M2MLinkedCountColumn(
        viewname="extras:tag_list", url_params={"slug": ("object_tags", "slug")}, verbose_name="Object Tags"
    )
    default_image = BooleanColumn()
    actions = ButtonsColumn(SoftwareImageLCM, buttons=("edit", "delete"))

    class Meta(BaseTable.Meta):  # pylint: disable=too-few-public-methods
        """Meta attributes."""

        model = SoftwareImageLCM
        fields = (
            "pk",
            "name",
            "software",
            "device_type_count",
            "object_tag_count",
            "default_image",
            "actions",
        )


class ValidatedSoftwareLCMTable(BaseTable):
    """Table for ValidatedSoftwareLCMListView."""

    pk = ToggleColumn()
    name = tables.LinkColumn(
        "plugins:nautobot_device_lifecycle_mgmt:validatedsoftwarelcm",
        text=lambda record: record,
        args=[
            A("pk"),
        ],
        orderable=False,
    )
    valid = BooleanColumn(verbose_name="Valid Now", orderable=False)
    software = tables.LinkColumn(verbose_name="Software")
    actions = ButtonsColumn(ValidatedSoftwareLCM, buttons=("edit", "delete"))
    preferred = BooleanColumn()

    class Meta(BaseTable.Meta):  # pylint: disable=too-few-public-methods
        """Meta attributes."""

        model = ValidatedSoftwareLCM
        fields = (
            "pk",
            "name",
            "software",
            "start",
            "end",
            "valid",
            "preferred",
            "actions",
        )


class DeviceSoftwareValidationResultTable(BaseTable):
    """Table for device software validation report."""

    name = tables.Column(accessor="device__device_type__model", verbose_name="Device Type")
    total = tables.Column(accessor="total", verbose_name="Total")
    valid = tables.Column(accessor="valid", verbose_name="Valid")
    invalid = tables.Column(accessor="invalid", verbose_name="Invalid")
    no_software = tables.Column(accessor="no_software", verbose_name="No Software")
    valid_percent = PercentageColumn(accessor="valid_percent", verbose_name="Compliance (%)")

    class Meta(BaseTable.Meta):  # pylint: disable=too-few-public-methods
        """Metaclass attributes of DeviceSoftwareValidationResultTable."""

        model = DeviceSoftwareValidationResult
        fields = ["name", "total", "valid", "invalid", "no_software", "valid_percent"]
        default_columns = [
            "name",
            "total",
            "valid",
            "invalid",
            "no_software",
            "valid_percent",
        ]


class InventoryItemSoftwareValidationResultTable(BaseTable):
    """Table for inventory item software validation report."""

    part_id = tables.Column(accessor="inventory_item__part_id", verbose_name="Part ID")
    total = tables.Column(accessor="total", verbose_name="Total")
    valid = tables.Column(accessor="valid", verbose_name="Valid")
    invalid = tables.Column(accessor="invalid", verbose_name="Invalid")
    no_software = tables.Column(accessor="no_software", verbose_name="No Software")
    valid_percent = PercentageColumn(accessor="valid_percent", verbose_name="Compliance (%)")

    class Meta(BaseTable.Meta):  # pylint: disable=too-few-public-methods
        """Metaclass attributes of InventoryItemSoftwareValidationResultTable."""

        model = InventoryItemSoftwareValidationResult
        fields = ["part_id", "total", "valid", "invalid", "no_software", "valid_percent"]
        default_columns = [
            "part_id",
            "total",
            "valid",
            "invalid",
            "no_software",
            "valid_percent",
        ]


class ContractLCMTable(BaseTable):
    """Table for list view."""

    pk = ToggleColumn()
    name = tables.LinkColumn(
        "plugins:nautobot_device_lifecycle_mgmt:contractlcm", text=lambda record: record, args=[A("pk")]
    )
    provider = tables.LinkColumn(
        "plugins:nautobot_device_lifecycle_mgmt:providerlcm",
        text=lambda record: record.provider,
        args=[A("provider.pk")],
    )
    cost = tables.TemplateColumn(
        template_code="""{{ record.cost }}{% if record.currency %} {{ record.currency }}{% endif %}"""
    )
    actions = ButtonsColumn(ContractLCM, buttons=("changelog", "edit", "delete"))

    class Meta(BaseTable.Meta):  # pylint: disable=too-few-public-methods
        """Meta attributes."""

        model = ContractLCM
        fields = (
            "pk",
            "name",
            "start",
            "end",
            "cost",
            "support_level",
            "contract_type",
            "provider",
            "actions",
        )


class ProviderLCMTable(BaseTable):
    """Table for list view."""

    pk = ToggleColumn()
    name = tables.LinkColumn(
        "plugins:nautobot_device_lifecycle_mgmt:providerlcm", text=lambda record: record, args=[A("pk")]
    )
    portal_url = tables.TemplateColumn(
        template_code="""{% if record.portal_url %}
                    <a href="{{ record.portal_url }}" target="_blank" data-toggle="tooltip" data-placement="left" title="{{ record.portal_url }}">
                        <span class="mdi mdi-open-in-new"></span>
                    </a>{% else %} — {% endif %}""",
        verbose_name="URL",
    )
    actions = ButtonsColumn(ProviderLCM, buttons=("changelog", "edit", "delete"))

    class Meta(BaseTable.Meta):  # pylint: disable=too-few-public-methods
        """Meta attributes."""

        model = ProviderLCM
        fields = (
            "pk",
            "name",
            "physical_address",
            "phone",
            "email",
            "portal_url",
            "actions",
        )


class ContactLCMTable(BaseTable):
    """Table for list view."""

    pk = ToggleColumn()
    name = tables.LinkColumn(
        "plugins:nautobot_device_lifecycle_mgmt:contactlcm", text=lambda record: record, args=[A("pk")]
    )
    actions = ButtonsColumn(ContactLCM, buttons=("changelog", "edit", "delete"))

    class Meta(BaseTable.Meta):  # pylint: disable=too-few-public-methods
        """Meta attributes."""

        model = ContactLCM
        fields = (
            "pk",
            "name",
            "address",
            "phone",
            "email",
            "comments",
            "priority",
            "contract",
            "actions",
        )


class CVELCMTable(StatusTableMixin, BaseTable):
    """Table for list view."""

    model = CVELCM
    pk = ToggleColumn()
    name = tables.LinkColumn(
        "plugins:nautobot_device_lifecycle_mgmt:cvelcm", text=lambda record: record, args=[A("pk")]
    )
    link = tables.TemplateColumn(
        template_code="""{% if record.link %}
                    <a href="{{ record.link }}" target="_blank" data-toggle="tooltip" data-placement="left" title="{{ record.link }}">
                        <span class="mdi mdi-open-in-new"></span>
                    </a>
                    {% else %}
                    —
                    {% endif %}""",
        verbose_name="Link",
    )
    tags = TagColumn()
    actions = ButtonsColumn(CVELCM, buttons=("changelog", "edit", "delete"))

    class Meta(BaseTable.Meta):  # pylint: disable=too-few-public-methods
        """Meta attributes."""

        model = CVELCM
        fields = (
            "pk",
            "name",
            "published_date",
            "last_modified_date",
            "link",
            "severity",
            "cvss",
            "cvss_v2",
            "cvss_v3",
            "status",
            "tags",
            "actions",
        )
        default_columns = (
            "pk",
            "name",
            "published_date",
            "last_modified_date",
            "link",
            "severity",
            "cvss",
            "cvss_v2",
            "cvss_v3",
            "status",
            "actions",
        )


class VulnerabilityLCMTable(StatusTableMixin, BaseTable):
    """Table for list view."""

    model = VulnerabilityLCM
    pk = ToggleColumn()
    name = tables.LinkColumn(
        "plugins:nautobot_device_lifecycle_mgmt:vulnerabilitylcm", text=lambda record: record, args=[A("pk")]
    )
    cve = tables.LinkColumn(verbose_name="CVE")
    software = tables.LinkColumn()
    device = tables.LinkColumn()
    inventory_item = tables.LinkColumn(verbose_name="Inventory Item")
    tags = TagColumn()
    actions = ButtonsColumn(VulnerabilityLCM, buttons=("changelog", "edit", "delete"))

    class Meta(BaseTable.Meta):  # pylint: disable=too-few-public-methods
        """Meta attributes."""

        model = VulnerabilityLCM
        fields = (
            "pk",
            "name",
            "cve",
            "software",
            "device",
            "inventory_item",
            "status",
            "tags",
            "actions",
        )
        default_columns = (
            "pk",
            "name",
            "cve",
            "software",
            "device",
            "inventory_item",
            "status",
            "actions",
        )
