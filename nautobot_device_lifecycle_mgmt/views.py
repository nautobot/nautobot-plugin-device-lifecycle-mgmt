"""Views implementation for the Lifecycle Management plugin."""
import base64
import io
import logging
import urllib

import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
import numpy as np

from django.db.models import Q, F, Count, ExpressionWrapper, FloatField
from django_tables2 import RequestConfig

from nautobot.core.views import generic
from nautobot.dcim.models import Device
from nautobot.utilities.paginator import EnhancedPaginator, get_paginate_count
from nautobot.utilities.views import ContentTypePermissionRequiredMixin
from nautobot_device_lifecycle_mgmt import choices
from nautobot_device_lifecycle_mgmt.models import (
    HardwareLCM,
    SoftwareLCM,
    ContactLCM,
    ValidatedSoftwareLCM,
    DeviceSoftwareValidationResult,
    InventoryItemSoftwareValidationResult,
    ContractLCM,
    ProviderLCM,
    CVELCM,
    VulnerabilityLCM,
    SoftwareImageLCM,
)
from nautobot_device_lifecycle_mgmt.tables import (
    HardwareLCMTable,
    SoftwareLCMTable,
    ValidatedSoftwareLCMTable,
    DeviceSoftwareValidationResultTable,
    InventoryItemSoftwareValidationResultTable,
    ContractLCMTable,
    ProviderLCMTable,
    ContactLCMTable,
    CVELCMTable,
    VulnerabilityLCMTable,
    SoftwareImageLCMTable,
)
from nautobot_device_lifecycle_mgmt.forms import (
    HardwareLCMForm,
    HardwareLCMBulkEditForm,
    HardwareLCMFilterForm,
    HardwareLCMCSVForm,
    SoftwareLCMForm,
    SoftwareLCMFilterForm,
    SoftwareLCMCSVForm,
    ValidatedSoftwareLCMForm,
    ValidatedSoftwareLCMFilterForm,
    ValidatedSoftwareLCMCSVForm,
    DeviceSoftwareValidationResultFilterForm,
    InventoryItemSoftwareValidationResultFilterForm,
    ContractLCMForm,
    ContractLCMBulkEditForm,
    ContractLCMFilterForm,
    ContractLCMCSVForm,
    ProviderLCMForm,
    ProviderLCMBulkEditForm,
    ProviderLCMFilterForm,
    ProviderLCMCSVForm,
    ContactLCMForm,
    ContactLCMBulkEditForm,
    ContactLCMFilterForm,
    ContactLCMCSVForm,
    CVELCMForm,
    CVELCMFilterForm,
    CVELCMBulkEditForm,
    CVELCMCSVForm,
    VulnerabilityLCMForm,
    VulnerabilityLCMFilterForm,
    VulnerabilityLCMBulkEditForm,
    SoftwareImageLCMForm,
    SoftwareImageLCMFilterForm,
    SoftwareImageLCMCSVForm,
)
from nautobot_device_lifecycle_mgmt.filters import (
    HardwareLCMFilterSet,
    ContractLCMFilterSet,
    ProviderLCMFilterSet,
    ContactLCMFilterSet,
    SoftwareLCMFilterSet,
    ValidatedSoftwareLCMFilterSet,
    DeviceSoftwareValidationResultFilterSet,
    InventoryItemSoftwareValidationResultFilterSet,
    CVELCMFilterSet,
    VulnerabilityLCMFilterSet,
    SoftwareImageLCMFilterSet,
)

from nautobot_device_lifecycle_mgmt.const import URL, PLUGIN_CFG
from nautobot_device_lifecycle_mgmt.utils import count_related_m2m

logger = logging.getLogger("nautobot_device_lifecycle_mgmt")

# ---------------------------------------------------------------------------------
#  Hardware Lifecycle Management Views
# ---------------------------------------------------------------------------------
GREEN, RED, GREY = ("#D5E8D4", "#F8CECC", "#808080")


class HardwareLCMListView(generic.ObjectListView):
    """List view."""

    queryset = HardwareLCM.objects.prefetch_related("device_type")
    filterset = HardwareLCMFilterSet
    filterset_form = HardwareLCMFilterForm
    table = HardwareLCMTable


class HardwareLCMView(generic.ObjectView):
    """Detail view."""

    queryset = HardwareLCM.objects.prefetch_related("device_type")

    def get_extra_context(self, request, instance):
        """Return any additional context data for the template.

        request: The current request
        instance: The object being viewed
        """
        if instance.device_type:
            return {"devices": Device.objects.restrict(request.user, "view").filter(device_type=instance.device_type)}
        if instance.inventory_item:
            return {
                "devices": Device.objects.restrict(request.user, "view").filter(
                    inventoryitems__part_id=instance.inventory_item
                )
            }
        return {"devices": []}


class HardwareLCMCreateView(generic.ObjectEditView):
    """Create view."""

    model = HardwareLCM
    queryset = HardwareLCM.objects.prefetch_related("device_type")
    model_form = HardwareLCMForm
    template_name = "nautobot_device_lifecycle_mgmt/hardwarelcm_edit.html"
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:hardwarelcm_list"


class HardwareLCMDeleteView(generic.ObjectDeleteView):
    """Delete view."""

    model = HardwareLCM
    queryset = HardwareLCM.objects.prefetch_related("device_type")
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:hardwarelcm_list"


class HardwareLCMEditView(generic.ObjectEditView):
    """Edit view."""

    model = HardwareLCM
    queryset = HardwareLCM.objects.prefetch_related("device_type")
    model_form = HardwareLCMForm
    template_name = "nautobot_device_lifecycle_mgmt/hardwarelcm_edit.html"
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:hardwarelcm"


class HardwareLCMBulkImportView(generic.BulkImportView):
    """View for bulk import of hardware lcm."""

    queryset = HardwareLCM.objects.prefetch_related("device_type")
    model_form = HardwareLCMCSVForm
    table = HardwareLCMTable
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:hardwarelcm_list"


class HardwareLCMBulkDeleteView(generic.BulkDeleteView):
    """View for deleting one or more HardwareLCM records."""

    queryset = HardwareLCM.objects.prefetch_related("device_type")
    table = HardwareLCMTable
    bulk_delete_url = "plugins:nautobot_device_lifecycle_mgmt.hardwarelcm_bulk_delete"
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:hardwarelcm_list"


class HardwareLCMBulkEditView(generic.BulkEditView):
    """View for editing one or more HardwareLCM records."""

    queryset = HardwareLCM.objects.prefetch_related("device_type")
    filterset = HardwareLCMFilterSet
    table = HardwareLCMTable
    form = HardwareLCMBulkEditForm
    bulk_edit_url = "plugins:nautobot_device_lifecycle_mgmt.hardwarelcm_bulk_edit"


class SoftwareLCMListView(generic.ObjectListView):
    """SoftwareLCM List view."""

    queryset = SoftwareLCM.objects.prefetch_related("device_platform")
    filterset = SoftwareLCMFilterSet
    filterset_form = SoftwareLCMFilterForm
    table = SoftwareLCMTable
    action_buttons = (
        "add",
        "import",
        "export",
    )
    template_name = "nautobot_device_lifecycle_mgmt/softwarelcm_list.html"


class SoftwareLCMView(generic.ObjectView):
    """SoftwareLCM Detail view."""

    queryset = SoftwareLCM.objects.prefetch_related("device_platform")

    def get_extra_context(self, request, instance):
        """Display SoftwareImageLCM objects associated with the SoftwareLCM object."""
        softwareimages = instance.software_images.restrict(request.user, "view")
        if softwareimages.exists():
            softwareimages_table = SoftwareImageLCMTable(data=softwareimages, user=request.user, orderable=False)
        else:
            softwareimages_table = None

        extra_context = {
            "softwareimages_table": softwareimages_table,
        }

        return extra_context


class SoftwareLCMCreateView(generic.ObjectEditView):
    """SoftwareLCM Create view."""

    model = SoftwareLCM
    queryset = SoftwareLCM.objects.prefetch_related("device_platform")
    model_form = SoftwareLCMForm
    default_return_url = URL.SoftwareLCM.List


class SoftwareLCMDeleteView(generic.ObjectDeleteView):
    """SoftwareLCM Delete view."""

    model = SoftwareLCM
    queryset = SoftwareLCM.objects.prefetch_related("device_platform")
    default_return_url = URL.SoftwareLCM.List
    template_name = "nautobot_device_lifecycle_mgmt/softwarelcm_delete.html"


class SoftwareLCMEditView(generic.ObjectEditView):
    """SoftwareLCM Edit view."""

    model = SoftwareLCM
    queryset = SoftwareLCM.objects.prefetch_related("device_platform")
    model_form = SoftwareLCMForm
    default_return_url = URL.SoftwareLCM.View


class SoftwareLCMBulkImportView(generic.BulkImportView):
    """View for bulk import of SoftwareLCM."""

    queryset = SoftwareLCM.objects.prefetch_related("device_platform")
    model_form = SoftwareLCMCSVForm
    table = SoftwareLCMTable
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:softwarelcm_list"


class SoftwareSoftwareImagesLCMView(generic.ObjectView):
    """Software Images tab for Software view."""

    queryset = SoftwareLCM.objects.all()
    template_name = "nautobot_device_lifecycle_mgmt/softwarelcm_software_images.html"

    def get_extra_context(self, request, instance):
        """Adds Software Images table."""
        softwareimages = (
            instance.software_images.annotate(device_type_count=count_related_m2m(SoftwareImageLCM, "device_types"))
            .annotate(object_tag_count=count_related_m2m(SoftwareImageLCM, "object_tags"))
            .restrict(request.user, "view")
        )

        softwareimages_table = SoftwareImageLCMTable(data=softwareimages, user=request.user, orderable=False)

        paginate = {
            "paginator_class": EnhancedPaginator,
            "per_page": get_paginate_count(request),
        }
        RequestConfig(request, paginate).configure(softwareimages_table)

        return {
            "softwareimages_table": softwareimages_table,
            "active_tab": "software-images",
        }


class SoftwareImageLCMListView(generic.ObjectListView):
    """SoftwareImageLCM List view."""

    queryset = SoftwareImageLCM.objects.annotate(
        device_type_count=count_related_m2m(SoftwareImageLCM, "device_types")
    ).annotate(object_tag_count=count_related_m2m(SoftwareImageLCM, "object_tags"))
    filterset = SoftwareImageLCMFilterSet
    filterset_form = SoftwareImageLCMFilterForm
    table = SoftwareImageLCMTable
    action_buttons = (
        "add",
        "import",
        "export",
    )
    template_name = "nautobot_device_lifecycle_mgmt/softwareimagelcm_list.html"


class SoftwareImageLCMView(generic.ObjectView):
    """SoftwareImageLCM Detail view."""

    queryset = SoftwareImageLCM.objects.all()


class SoftwareImageLCMEditView(generic.ObjectEditView):
    """SoftwareImageLCM Create/Edit view."""

    queryset = SoftwareImageLCM.objects.all()
    model_form = SoftwareImageLCMForm
    template_name = "nautobot_device_lifecycle_mgmt/softwareimagelcm_edit.html"
    default_return_url = URL.SoftwareImageLCM.List


class SoftwareImageLCMDeleteView(generic.ObjectDeleteView):
    """SoftwareImageLCM Delete view."""

    model = SoftwareImageLCM
    queryset = SoftwareImageLCM.objects.all()
    default_return_url = URL.SoftwareImageLCM.List
    template_name = "nautobot_device_lifecycle_mgmt/softwareimagelcm_delete.html"


class SoftwareImageLCMBulkDeleteView(generic.BulkDeleteView):
    """View for deleting one or more SoftwareImageLCM objects."""

    queryset = SoftwareImageLCM.objects.all()
    table = SoftwareImageLCMTable
    bulk_delete_url = "plugins:nautobot_device_lifecycle_mgmt.softwareimagelcm_bulk_delete"
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:softwareimagelcm_list"


class SoftwareImageLCMBulkImportView(generic.BulkImportView):
    """View for bulk import of SoftwareImageLCM."""

    queryset = SoftwareImageLCM.objects.all()
    model_form = SoftwareImageLCMCSVForm
    table = SoftwareImageLCMTable
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:softwareimagelcm_list"


class ValidatedSoftwareLCMListView(generic.ObjectListView):
    """ValidatedSoftware List view."""

    queryset = ValidatedSoftwareLCM.objects.all()
    filterset = ValidatedSoftwareLCMFilterSet
    filterset_form = ValidatedSoftwareLCMFilterForm
    table = ValidatedSoftwareLCMTable
    action_buttons = (
        "add",
        "import",
        "export",
    )
    template_name = "nautobot_device_lifecycle_mgmt/validatedsoftwarelcm_list.html"


class ValidatedSoftwareLCMView(generic.ObjectView):
    """ValidatedSoftware Detail view."""

    queryset = ValidatedSoftwareLCM.objects.all()


class ValidatedSoftwareLCMEditView(generic.ObjectEditView):
    """ValidatedSoftware Create view."""

    queryset = ValidatedSoftwareLCM.objects.all()
    model_form = ValidatedSoftwareLCMForm
    template_name = "nautobot_device_lifecycle_mgmt/validatedsoftwarelcm_edit.html"
    default_return_url = URL.ValidatedSoftwareLCM.List


class ValidatedSoftwareLCMDeleteView(generic.ObjectDeleteView):
    """SoftwareLCM Delete view."""

    model = ValidatedSoftwareLCM
    queryset = ValidatedSoftwareLCM.objects.all()
    default_return_url = URL.ValidatedSoftwareLCM.List
    template_name = "nautobot_device_lifecycle_mgmt/validatedsoftwarelcm_delete.html"


class ValidatedSoftwareLCMBulkImportView(generic.BulkImportView):
    """View for bulk import of ValidatedSoftwareLCM."""

    queryset = ValidatedSoftwareLCM.objects.all()
    model_form = ValidatedSoftwareLCMCSVForm
    table = ValidatedSoftwareLCMTable
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:validatedsoftwarelcm_list"


class ReportOverviewHelper(ContentTypePermissionRequiredMixin, generic.View):
    """Customized overview view for reports aggregation and filterset."""

    def get_required_permission(self):
        """Manually set permission when not tied to a model for global report."""
        # TODO: more generic permission should be used here
        return "nautobot_device_lifecycle_mgmt.view_validatedsoftwarelcm"

    @staticmethod
    def url_encode_figure(figure):
        """Save graph into string buffer and convert 64 bit code into image."""
        buf = io.BytesIO()
        figure.savefig(buf, format="png")
        buf.seek(0)
        string = base64.b64encode(buf.read())

        return urllib.parse.quote(string)

    @staticmethod
    def plot_piechart_visual(aggr, pie_chart_attrs):
        """Plot pie chart aggregation visual."""
        if aggr[pie_chart_attrs["aggr_labels"][0]] is None:
            return None

        colors = [GREEN, RED, GREY]
        sizes = []
        pie_chart_labels = []
        pie_chart_colors = []
        for aggr_label, chart_label, color in zip(
            pie_chart_attrs["aggr_labels"], pie_chart_attrs["chart_labels"], colors
        ):
            if aggr[aggr_label] == 0:
                continue
            sizes.append(aggr[aggr_label])
            pie_chart_labels.append(chart_label)
            pie_chart_colors.append(color)

        explode = len(sizes) * (0.1,)
        fig1, ax1 = plt.subplots()
        logging.debug(fig1)
        ax1.pie(
            sizes,
            explode=explode,
            labels=pie_chart_labels,
            autopct="%1.1f%%",
            colors=pie_chart_colors,
            shadow=True,
            startangle=90,
            normalize=True,
        )
        ax1.axis("equal")  # Equal aspect ratio ensures that pie is drawn as a circle.
        plt.title(aggr["name"], y=-0.1)
        fig = plt.gcf()

        return ReportOverviewHelper.url_encode_figure(fig)

    @staticmethod
    def plot_barchart_visual(qs, chart_attrs):  # pylint: disable=too-many-locals
        """Construct report visual from queryset."""
        labels = [item[chart_attrs["label_accessor"]] for item in qs]

        label_locations = np.arange(len(labels))  # the label locations

        barchart_bar_width = PLUGIN_CFG["barchart_bar_width"]
        barchart_width = PLUGIN_CFG["barchart_width"]
        barchart_height = PLUGIN_CFG["barchart_height"]

        width = barchart_bar_width  # the width of the bars

        fig, axis = plt.subplots(figsize=(barchart_width, barchart_height))

        rects = []
        for bar_pos, chart_bar in enumerate(chart_attrs["chart_bars"]):
            bar_label_item = [item[chart_bar["data_attr"]] for item in qs]
            rects.append(
                axis.bar(
                    label_locations - width + (bar_pos * width),
                    bar_label_item,
                    width,
                    label=chart_bar["label"],
                    color=chart_bar["color"],
                )
            )

        # Add some text for labels, title and custom x-axis tick labels, etc.
        axis.set_ylabel(chart_attrs["ylabel"])
        axis.set_title(chart_attrs["title"])
        axis.set_xticks(label_locations)
        axis.set_xticklabels(labels, rotation=0)
        # Force integer y-axis labels
        axis.yaxis.set_major_locator(MaxNLocator(integer=True))
        axis.margins(0.2, 0.2)
        axis.legend()

        def autolabel(rects):
            """Attach a text label above each bar in *rects*, displaying its height."""
            for rect in rects:
                height = rect.get_height()
                axis.annotate(
                    f"{height}",
                    xy=(rect.get_x() + rect.get_width() / 2, 0.5),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha="center",
                    va="bottom",
                    rotation=90,
                )

        for rect in rects:
            autolabel(rect)

        return ReportOverviewHelper.url_encode_figure(fig)

    @staticmethod
    def calculate_aggr_percentage(aggr):
        """Calculate percentage of validated given aggregation fields.

        Returns:
            aggr: same aggr dict given as parameter with one new key
                - valid_percent
        """
        try:
            aggr["valid_percent"] = round(aggr["valid"] / aggr["total"] * 100, 2)
        except ZeroDivisionError:
            aggr["valid_percent"] = 0
        return aggr


class ValidatedSoftwareDeviceReportView(generic.ObjectListView):
    """View for executive report on software Validation."""

    filterset = DeviceSoftwareValidationResultFilterSet
    filterset_form = DeviceSoftwareValidationResultFilterForm
    table = DeviceSoftwareValidationResultTable
    template_name = "nautobot_device_lifecycle_mgmt/validatedsoftware_device_report.html"
    queryset = (
        DeviceSoftwareValidationResult.objects.values("device__device_type__model")
        .distinct()
        .annotate(
            total=Count("device__device_type__model"),
            valid=Count("device__device_type__model", filter=Q(is_validated=True)),
            invalid=Count("device__device_type__model", filter=Q(is_validated=False) & ~Q(software=None)),
            no_software=Count("device__device_type__model", filter=Q(software=None)),
            valid_percent=ExpressionWrapper(100 * F("valid") / (F("total")), output_field=FloatField()),
        )
        .order_by("-valid_percent")
    )

    # extra content dict to be returned by self.extra_context() method
    extra_content = {}

    def setup(self, request, *args, **kwargs):
        """Using request object to perform filtering based on query params."""
        super().setup(request, *args, **kwargs)  #
        try:
            report_last_run = (
                DeviceSoftwareValidationResult.objects.filter(run_type=choices.ReportRunTypeChoices.REPORT_FULL_RUN)
                .latest("last_updated")
                .last_run
            )
        except DeviceSoftwareValidationResult.DoesNotExist:
            report_last_run = None

        device_aggr = self.get_global_aggr(request)
        _platform_qs = (
            DeviceSoftwareValidationResult.objects.values("device__platform__name")
            .distinct()
            .annotate(
                total=Count("device__platform__name"),
                valid=Count("device__platform__name", filter=Q(is_validated=True)),
                invalid=Count("device__platform__name", filter=Q(is_validated=False) & ~Q(software=None)),
                no_software=Count("device__platform__name", filter=Q(software=None)),
            )
            .order_by("-total")
        )
        platform_qs = self.filterset(request.GET, _platform_qs).qs
        pie_chart_attrs = {
            "aggr_labels": ["valid", "invalid", "no_software"],
            "chart_labels": ["Valid", "Invalid", "No Software"],
        }
        bar_chart_attrs = {
            "label_accessor": "device__platform__name",
            "ylabel": "Device",
            "title": "Valid per Platform",
            "chart_bars": [
                {"label": "Valid", "data_attr": "valid", "color": GREEN},
                {"label": "Invalid", "data_attr": "invalid", "color": RED},
                {"label": "No Software", "data_attr": "no_software", "color": GREY},
            ],
        }
        self.extra_content = {
            "bar_chart": ReportOverviewHelper.plot_barchart_visual(platform_qs, bar_chart_attrs),
            "device_aggr": device_aggr,
            "device_visual": ReportOverviewHelper.plot_piechart_visual(device_aggr, pie_chart_attrs),
            "report_last_run": report_last_run,
        }

    def get_global_aggr(self, request):
        """Get device and inventory global reports.

        Returns:
            device_aggr: device global report dict
        """
        device_qs = DeviceSoftwareValidationResult.objects

        device_aggr = {}
        if self.filterset is not None:
            device_aggr = self.filterset(request.GET, device_qs).qs.aggregate(
                total=Count("device"),
                valid=Count("device", filter=Q(is_validated=True)),
                invalid=Count("device", filter=Q(is_validated=False) & ~Q(software=None)),
                no_software=Count("device", filter=Q(software=None)),
            )

            device_aggr["name"] = "Devices"

        return ReportOverviewHelper.calculate_aggr_percentage(device_aggr)

    def extra_context(self):
        """Extra content method on."""
        # add global aggregations to extra context.

        return self.extra_content

    def queryset_to_csv(self):
        """Export queryset of objects as comma-separated value (CSV)."""
        csv_data = []

        csv_data.append(",".join(["Type", "Total", "Valid", "Invalid", "No Software", "Compliance"]))
        csv_data.append(
            ",".join(
                ["Devices"]
                + [
                    f"{str(val)} %" if key == "valid_percent" else str(val)
                    for key, val in self.extra_content["device_aggr"].items()
                    if key != "name"
                ]
            )
        )
        csv_data.append(",".join([]))

        qs = self.queryset.values(
            "device__device_type__model", "total", "valid", "invalid", "no_software", "valid_percent"
        )
        csv_data.append(
            ",".join(
                [
                    "Device Model" if item == "device__device_type__model" else item.replace("_", " ").title()
                    for item in qs[0].keys()
                ]
            )
        )
        for obj in qs:
            csv_data.append(
                ",".join([f"{str(val)} %" if key == "valid_percent" else str(val) for key, val in obj.items()])
            )

        return "\n".join(csv_data)


class ValidatedSoftwareInventoryItemReportView(generic.ObjectListView):
    """View for executive report on inventory item software validation."""

    filterset = InventoryItemSoftwareValidationResultFilterSet
    filterset_form = InventoryItemSoftwareValidationResultFilterForm
    table = InventoryItemSoftwareValidationResultTable
    template_name = "nautobot_device_lifecycle_mgmt/validatedsoftware_inventoryitem_report.html"
    queryset = (
        InventoryItemSoftwareValidationResult.objects.values("inventory_item__part_id")
        .distinct()
        .annotate(
            total=Count("inventory_item__part_id"),
            valid=Count("inventory_item__part_id", filter=Q(is_validated=True)),
            invalid=Count("inventory_item__part_id", filter=Q(is_validated=False) & ~Q(software=None)),
            no_software=Count("inventory_item__part_id", filter=Q(software=None)),
            valid_percent=ExpressionWrapper(100 * F("valid") / (F("total")), output_field=FloatField()),
        )
        .order_by("-valid_percent")
    )

    # extra content dict to be returned by self.extra_context() method
    extra_content = {}

    def setup(self, request, *args, **kwargs):
        """Using request object to perform filtering based on query params."""
        super().setup(request, *args, **kwargs)
        try:
            report_last_run = (
                InventoryItemSoftwareValidationResult.objects.filter(
                    run_type=choices.ReportRunTypeChoices.REPORT_FULL_RUN
                )
                .latest("last_updated")
                .last_run
            )
        except InventoryItemSoftwareValidationResult.DoesNotExist:
            report_last_run = None

        inventory_aggr = self.get_global_aggr(request)
        _platform_qs = (
            InventoryItemSoftwareValidationResult.objects.values("inventory_item__manufacturer__name")
            .distinct()
            .annotate(
                total=Count("inventory_item__manufacturer__name"),
                valid=Count("inventory_item__manufacturer__name", filter=Q(is_validated=True)),
                invalid=Count("inventory_item__manufacturer__name", filter=Q(is_validated=False) & ~Q(software=None)),
                no_software=Count("inventory_item__manufacturer__name", filter=Q(software=None)),
            )
            .order_by("-total")
        )
        platform_qs = self.filterset(request.GET, _platform_qs).qs

        pie_chart_attrs = {
            "aggr_labels": ["valid", "invalid", "no_software"],
            "chart_labels": ["Valid", "Invalid", "No Software"],
        }
        bar_chart_attrs = {
            "label_accessor": "inventory_item__manufacturer__name",
            "ylabel": "Inventory Item",
            "title": "Valid per Manufacturer",
            "chart_bars": [
                {"label": "Valid", "data_attr": "valid", "color": GREEN},
                {"label": "Invalid", "data_attr": "invalid", "color": RED},
                {"label": "No Software", "data_attr": "no_software", "color": GREY},
            ],
        }

        self.extra_content = {
            "bar_chart": ReportOverviewHelper.plot_barchart_visual(platform_qs, bar_chart_attrs),
            "inventory_aggr": inventory_aggr,
            "inventory_visual": ReportOverviewHelper.plot_piechart_visual(inventory_aggr, pie_chart_attrs),
            "report_last_run": report_last_run,
        }

    def get_global_aggr(self, request):
        """Get device and inventory global reports.

        Returns:
            inventory_aggr: inventory item global report dict
        """
        inventory_item_qs = InventoryItemSoftwareValidationResult.objects

        inventory_aggr = {}
        if self.filterset is not None:
            inventory_aggr = self.filterset(request.GET, inventory_item_qs).qs.aggregate(
                total=Count("inventory_item"),
                valid=Count("inventory_item", filter=Q(is_validated=True)),
                invalid=Count("inventory_item", filter=Q(is_validated=False) & ~Q(software=None)),
                no_software=Count("inventory_item", filter=Q(software=None)),
            )
            inventory_aggr["name"] = "Inventory Items"

        return ReportOverviewHelper.calculate_aggr_percentage(inventory_aggr)

    def extra_context(self):
        """Extra content method on."""
        # add global aggregations to extra context.

        return self.extra_content

    def queryset_to_csv(self):
        """Export queryset of objects as comma-separated value (CSV)."""
        csv_data = []

        csv_data.append(",".join(["Type", "Total", "Valid", "Invalid", "No Software", "Compliance"]))
        csv_data.append(
            ",".join(
                ["Inventory Items"]
                + [
                    f"{str(val)} %" if key == "valid_percent" else str(val)
                    for key, val in self.extra_content["inventory_aggr"].items()
                    if key != "name"
                ]
            )
        )
        csv_data.append(",".join([]))

        qs = self.queryset.values(
            "inventory_item__part_id", "total", "valid", "invalid", "no_software", "valid_percent"
        )
        csv_data.append(
            ",".join(
                [
                    "Part ID" if item == "inventory_item__part_id" else item.replace("_", " ").title()
                    for item in qs[0].keys()
                ]
            )
        )
        for obj in qs:
            csv_data.append(
                ",".join([f"{str(val)} %" if key == "valid_percent" else str(val) for key, val in obj.items()])
            )

        return "\n".join(csv_data)


# ---------------------------------------------------------------------------------
#  Contract Lifecycle Management Views
# ---------------------------------------------------------------------------------


class ContractLCMListView(generic.ObjectListView):
    """List view."""

    queryset = ContractLCM.objects.all()
    filterset = ContractLCMFilterSet
    filterset_form = ContractLCMFilterForm
    table = ContractLCMTable


class ContractLCMView(generic.ObjectView):
    """Detail view."""

    queryset = ContractLCM.objects.all()

    def get_extra_context(self, request, instance):
        """Return any additional context data for the template.

        request: The current request
        instance: The object being viewed
        """
        return {
            "contacts": ContactLCM.objects.restrict(request.user, "view")
            .filter(contract=instance)
            .exclude(type="Owner")
            .order_by("type", "priority"),
            "owners": ContactLCM.objects.restrict(request.user, "view")
            .filter(contract=instance, type="Owner")
            .order_by("type", "priority"),
        }


class ContractLCMCreateView(generic.ObjectEditView):
    """Create view."""

    model = ContractLCM
    queryset = ContractLCM.objects.all()
    model_form = ContractLCMForm
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:contractlcm_list"


class ContractLCMDeleteView(generic.ObjectDeleteView):
    """Delete view."""

    model = ContractLCM
    queryset = ContractLCM.objects.all()
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:contractlcm_list"


class ContractLCMEditView(generic.ObjectEditView):
    """Edit view."""

    model = ContractLCM
    queryset = ContractLCM.objects.all()
    model_form = ContractLCMForm
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:contractlcm"


class ContractLCMBulkImportView(generic.BulkImportView):
    """View for bulk import of hardware lcm."""

    queryset = ContractLCM.objects.all()
    model_form = ContractLCMCSVForm
    table = ContractLCMTable
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:contractlcm_list"


class ContractLCMBulkDeleteView(generic.BulkDeleteView):
    """View for deleting one or more HardwareLCM records."""

    queryset = ContractLCM.objects.all()
    table = ContractLCMTable
    bulk_delete_url = "plugins:nautobot_device_lifecycle_mgmt.contractlcm_bulk_delete"
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:contractlcm_list"


class ContractLCMBulkEditView(generic.BulkEditView):
    """View for editing one or more HardwareLCM records."""

    queryset = ContractLCM.objects.all()
    filterset = ContractLCMFilterSet
    table = ContractLCMTable
    form = ContractLCMBulkEditForm
    bulk_edit_url = "plugins:nautobot_device_lifecycle_mgmt.contractlcm_bulk_edit"


# ---------------------------------------------------------------------------------
#  Contract Provider Lifecycle Management Views
# ---------------------------------------------------------------------------------


class ProviderLCMListView(generic.ObjectListView):
    """List view."""

    queryset = ProviderLCM.objects.all()
    filterset = ProviderLCMFilterSet
    filterset_form = ProviderLCMFilterForm
    table = ProviderLCMTable


class ProviderLCMView(generic.ObjectView):
    """Detail view."""

    queryset = ProviderLCM.objects.all()

    def get_extra_context(self, request, instance):
        """Return any additional context data for the template.

        request: The current request
        instance: The object being viewed
        """
        return {"contracts": ContractLCM.objects.restrict(request.user, "view").filter(provider=instance)}


class ProviderLCMCreateView(generic.ObjectEditView):
    """Create view."""

    model = ProviderLCM
    queryset = ProviderLCM.objects.all()
    model_form = ProviderLCMForm
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:providerlcm_list"


class ProviderLCMDeleteView(generic.ObjectDeleteView):
    """Delete view."""

    model = ProviderLCM
    queryset = ProviderLCM.objects.all()
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:providerlcm_list"


class ProviderLCMEditView(generic.ObjectEditView):
    """Edit view."""

    model = ProviderLCM
    queryset = ProviderLCM.objects.all()
    model_form = ProviderLCMForm
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:providerlcm"


class ProviderLCMBulkImportView(generic.BulkImportView):
    """Bulk import view."""

    queryset = ProviderLCM.objects.all()
    model_form = ProviderLCMCSVForm
    table = ProviderLCMTable
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:providerlcm_list"


class ProviderLCMBulkDeleteView(generic.BulkDeleteView):
    """View for deleting one or more HardwareLCM records."""

    queryset = ProviderLCM.objects.all()
    table = ProviderLCMTable
    bulk_delete_url = "plugins:nautobot_device_lifecycle_mgmt.providerlcm_bulk_delete"
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:providerlcm_list"


class ProviderLCMBulkEditView(generic.BulkEditView):
    """View for editing one or more HardwareLCM records."""

    queryset = ProviderLCM.objects.all()
    filterset = ProviderLCMFilterSet
    table = ProviderLCMTable
    form = ProviderLCMBulkEditForm
    bulk_edit_url = "plugins:nautobot_device_lifecycle_mgmt.providerlcm_bulk_edit"


# ---------------------------------------------------------------------------------
#  Contact POC Lifecycle Management Views
# ---------------------------------------------------------------------------------


class ContactLCMListView(generic.ObjectListView):
    """List view."""

    queryset = ContactLCM.objects.all()
    filterset = ContactLCMFilterSet
    filterset_form = ContactLCMFilterForm
    table = ContactLCMTable


class ContactLCMView(generic.ObjectView):
    """Detail view."""

    queryset = ContactLCM.objects.all()


class ContactLCMCreateView(generic.ObjectEditView):
    """Create view."""

    model = ContactLCM
    queryset = ContactLCM.objects.all()
    model_form = ContactLCMForm
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:contactlcm_list"


class ContactLCMDeleteView(generic.ObjectDeleteView):
    """Delete view."""

    model = ContactLCM
    queryset = ContactLCM.objects.all()
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:contactlcm_list"


class ContactLCMEditView(generic.ObjectEditView):
    """Edit view."""

    model = ContactLCM
    queryset = ContactLCM.objects.all()
    model_form = ContactLCMForm
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:contactlcm"


class ContactLCMBulkImportView(generic.BulkImportView):
    """Bulk import view."""

    queryset = ContactLCM.objects.all()
    model_form = ContactLCMCSVForm
    table = ContactLCMTable
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:contactlcm_list"


class ContactLCMBulkDeleteView(generic.BulkDeleteView):
    """View for deleting one or more records."""

    queryset = ContactLCM.objects.all()
    table = ContactLCMTable
    bulk_delete_url = "plugins:nautobot_device_lifecycle_mgmt.contactlcm_bulk_delete"
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:contactlcm_list"


class ContactLCMBulkEditView(generic.BulkEditView):
    """View for editing one or more records."""

    queryset = ContactLCM.objects.all()
    filterset = ContactLCMFilterSet
    table = ContactLCMTable
    form = ContactLCMBulkEditForm
    bulk_edit_url = "plugins:nautobot_device_lifecycle_mgmt.contactlcm_bulk_edit"


# ---------------------------------------------------------------------------------
#  CVE Lifecycle Management Views
# ---------------------------------------------------------------------------------


class CVELCMListView(generic.ObjectListView):
    """List view."""

    queryset = CVELCM.objects.all()
    filterset = CVELCMFilterSet
    filterset_form = CVELCMFilterForm
    table = CVELCMTable


class CVELCMView(generic.ObjectView):
    """Detail view."""

    queryset = CVELCM.objects.all()


class CVELCMCreateView(generic.ObjectEditView):
    """Create view."""

    model = CVELCM
    queryset = CVELCM.objects.all()
    model_form = CVELCMForm
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:cvelcm_list"


class CVELCMDeleteView(generic.ObjectDeleteView):
    """Delete view."""

    model = CVELCM
    queryset = CVELCM.objects.all()
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:cvelcm_list"


class CVELCMEditView(generic.ObjectEditView):
    """Edit view."""

    model = CVELCM
    queryset = CVELCM.objects.all()
    model_form = CVELCMForm
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:cvelcm"


class CVELCMBulkImportView(generic.BulkImportView):
    """View for bulk import of CVELCM."""

    queryset = CVELCM.objects.all()
    model_form = CVELCMCSVForm
    table = CVELCMTable
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:cvelcm_list"


class CVELCMBulkDeleteView(generic.BulkDeleteView):
    """View for deleting one or more CVELCM records."""

    queryset = CVELCM.objects.all()
    table = CVELCMTable
    bulk_delete_url = "plugins:nautobot_device_lifecycle_mgmt.cvelcm_bulk_delete"
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:cvelcm_list"


class CVELCMBulkEditView(generic.BulkEditView):
    """View for editing one or more CVELCM records."""

    queryset = CVELCM.objects.all()
    filterset = CVELCMFilterSet
    table = CVELCMTable
    form = CVELCMBulkEditForm
    bulk_edit_url = "plugins:nautobot_device_lifecycle_mgmt.cvelcm_bulk_edit"


# ---------------------------------------------------------------------------------
#  Vulnerability Lifecycle Management Views
# ---------------------------------------------------------------------------------


class VulnerabilityLCMListView(generic.ObjectListView):
    """List view."""

    queryset = VulnerabilityLCM.objects.all()
    filterset = VulnerabilityLCMFilterSet
    filterset_form = VulnerabilityLCMFilterForm
    table = VulnerabilityLCMTable
    action_buttons = ("export",)
    template_name = "nautobot_device_lifecycle_mgmt/vulnerabilitylcm_list.html"


class VulnerabilityLCMView(generic.ObjectView):
    """Detail view."""

    queryset = VulnerabilityLCM.objects.all()


class VulnerabilityLCMDeleteView(generic.ObjectDeleteView):
    """Delete view."""

    model = VulnerabilityLCM
    queryset = VulnerabilityLCM.objects.all()
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:vulnerabilitylcm_list"


class VulnerabilityLCMEditView(generic.ObjectEditView):
    """Edit view."""

    model = VulnerabilityLCM
    queryset = VulnerabilityLCM.objects.all()
    model_form = VulnerabilityLCMForm
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:vulnerabilitylcm"


class VulnerabilityLCMBulkDeleteView(generic.BulkDeleteView):
    """View for deleting one or more VulnerabilityLCM records."""

    queryset = VulnerabilityLCM.objects.all()
    table = VulnerabilityLCMTable
    bulk_delete_url = "plugins:nautobot_device_lifecycle_mgmt.vulnerabilitylcm_bulk_delete"
    default_return_url = "plugins:nautobot_device_lifecycle_mgmt:vulnerabilitylcm_list"


class VulnerabilityLCMBulkEditView(generic.BulkEditView):
    """View for editing one or more VulnerabilityLCM records."""

    queryset = VulnerabilityLCM.objects.all()
    filterset = VulnerabilityLCMFilterSet
    table = VulnerabilityLCMTable
    form = VulnerabilityLCMBulkEditForm
    bulk_edit_url = "plugins:nautobot_device_lifecycle_mgmt.vulnerabilitylcm_bulk_edit"
