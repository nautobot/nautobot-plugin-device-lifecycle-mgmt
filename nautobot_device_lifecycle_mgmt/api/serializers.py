"""API serializers implementation for the LifeCycle Management plugin."""
from rest_framework import serializers

from nautobot.core.api import SerializedPKRelatedField

from nautobot.dcim.api.nested_serializers import (
    NestedDeviceSerializer,
    NestedDeviceTypeSerializer,
    NestedPlatformSerializer,
    NestedInventoryItemSerializer,
)
from nautobot.extras.api.customfields import CustomFieldModelSerializer
from nautobot.extras.api.serializers import TaggedObjectSerializer, StatusModelSerializerMixin, StatusSerializerField
from nautobot.extras.models import Status

from nautobot_device_lifecycle_mgmt.models import (
    HardwareLCM,
    SoftwareImageLCM,
    SoftwareLCM,
    ContactLCM,
    ValidatedSoftwareLCM,
    ContractLCM,
    ProviderLCM,
    CVELCM,
    VulnerabilityLCM,
)

from .nested_serializers import (
    NestedSoftwareImageLCMSerializer,
    NestedSoftwareLCMSerializer,
    NestedProviderLCMSerializer,
    NestedContractLCMSerializer,
    NestedCVELCMSerializer,
)


class HardwareLCMSerializer(TaggedObjectSerializer, CustomFieldModelSerializer):  # pylint: disable=R0901
    """API serializer."""

    device_type = NestedDeviceTypeSerializer(
        many=False, read_only=False, required=True, help_text="Device Type to attach the Hardware LCM to"
    )
    devices = NestedDeviceSerializer(many=True, read_only=True, required=False, help_text="Devices tied to Device Type")

    class Meta:
        """Meta attributes."""

        model = HardwareLCM
        fields = [
            "id",
            "expired",
            "devices",
            "device_type",
            "inventory_item",
            "release_date",
            "end_of_sale",
            "end_of_support",
            "end_of_sw_releases",
            "end_of_security_patches",
            "documentation_url",
            "custom_fields",
            "tags",
        ]


class ProviderLCMSerializer(TaggedObjectSerializer, CustomFieldModelSerializer):  # pylint: disable=R0901
    """API serializer."""

    class Meta:
        """Meta attributes."""

        model = ProviderLCM
        fields = [
            "id",
            "name",
            "description",
            "physical_address",
            "phone",
            "email",
            "comments",
            "custom_fields",
            "tags",
        ]


class ContractLCMSerializer(TaggedObjectSerializer, CustomFieldModelSerializer):  # pylint: disable=R0901
    """API serializer."""

    provider = NestedProviderLCMSerializer(many=False, read_only=False, required=True, help_text="Vendor")

    class Meta:
        """Meta attributes."""

        model = ContractLCM
        fields = [
            "id",
            "provider",
            "name",
            "start",
            "end",
            "cost",
            "support_level",
            "contract_type",
            "expired",
            "custom_fields",
            "tags",
        ]


class ContactLCMSerializer(TaggedObjectSerializer, CustomFieldModelSerializer):  # pylint: disable=R0901
    """API serializer."""

    contract = NestedContractLCMSerializer(many=False, read_only=False, required=True, help_text="Associated Contract")

    class Meta:
        """Meta attributes."""

        model = ContactLCM
        fields = [
            "name",
            "address",
            "phone",
            "email",
            "comments",
            "priority",
            "contract",
            "custom_fields",
            "tags",
        ]


class SoftwareLCMSerializer(TaggedObjectSerializer, CustomFieldModelSerializer):  # pylint: disable=too-many-ancestors
    """REST API serializer for SoftwareLCM records."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:nautobot_device_lifecycle_mgmt-api:softwarelcm-detail"
    )
    device_platform = NestedPlatformSerializer()
    software_images = SerializedPKRelatedField(
        queryset=SoftwareImageLCM.objects.all(),
        serializer=NestedSoftwareImageLCMSerializer,
        required=False,
        many=True,
    )

    class Meta:
        """Meta attributes."""

        model = SoftwareLCM
        fields = [
            "id",
            "url",
            "device_platform",
            "version",
            "alias",
            "release_date",
            "end_of_support",
            "documentation_url",
            "software_images",
            "long_term_support",
            "pre_release",
            "custom_fields",
            "tags",
        ]


class SoftwareImageLCMSerializer(
    CustomFieldModelSerializer, TaggedObjectSerializer
):  # pylint: disable=too-many-ancestors
    """REST API serializer for SoftwareImageLCM records."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:nautobot_device_lifecycle_mgmt-api:softwareimagelcm-detail"
    )
    software = NestedSoftwareLCMSerializer()

    class Meta:
        """Meta attributes."""

        model = SoftwareImageLCM
        fields = [
            "id",
            "url",
            "image_file_name",
            "software",
            "device_types",
            "inventory_items",
            "object_tags",
            "download_url",
            "image_file_checksum",
            "default_image",
            "custom_fields",
            "tags",
        ]


class ValidatedSoftwareLCMSerializer(
    TaggedObjectSerializer, CustomFieldModelSerializer
):  # pylint: disable=too-many-ancestors
    """REST API serializer for ValidatedSoftwareLCM records."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:nautobot_device_lifecycle_mgmt-api:validatedsoftwarelcm-detail"
    )
    software = NestedSoftwareLCMSerializer()

    class Meta:
        """Meta attributes."""

        model = ValidatedSoftwareLCM
        fields = [
            "id",
            "url",
            "software",
            "devices",
            "device_types",
            "device_roles",
            "inventory_items",
            "object_tags",
            "start",
            "end",
            "preferred",
            "valid",
            "custom_fields",
            "tags",
        ]


class CVELCMSerializer(
    TaggedObjectSerializer, CustomFieldModelSerializer, StatusModelSerializerMixin
):  # pylint: disable=too-many-ancestors
    """REST API serializer for CVELCM records."""

    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nautobot_device_lifecycle_mgmt-api:cvelcm-detail")
    status = StatusSerializerField(required=False, queryset=Status.objects.all())

    class Meta:
        """Meta attributes."""

        model = CVELCM
        fields = [
            "id",
            "url",
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
            "custom_fields",
            "tags",
        ]


class VulnerabilityLCMSerializer(
    TaggedObjectSerializer, CustomFieldModelSerializer, StatusModelSerializerMixin
):  # pylint: disable=too-many-ancestors
    """REST API serializer for VulnerabilityLCM records."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:nautobot_device_lifecycle_mgmt-api:vulnerabilitylcm-detail"
    )
    cve = NestedCVELCMSerializer(read_only=True)
    software = NestedSoftwareLCMSerializer(read_only=True)
    device = NestedDeviceSerializer(read_only=True)
    inventory_item = NestedInventoryItemSerializer(read_only=True)

    class Meta:
        """Meta attributes."""

        model = VulnerabilityLCM
        fields = [
            "id",
            "display",
            "url",
            "cve",
            "software",
            "device",
            "inventory_item",
            "status",
            "custom_fields",
            "tags",
        ]
        read_only_fields = [
            "id",
            "display",
            "url",
            "cve",
            "software",
            "device",
            "inventory_item",
        ]
