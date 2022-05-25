"""Nested/brief alternate REST API serializers for nautobot_device_lifecycle_mgmt models."""

from rest_framework import serializers

from nautobot.core.api import WritableNestedSerializer

from nautobot_device_lifecycle_mgmt import models


class NestedSoftwareLCMSerializer(WritableNestedSerializer):
    """Nested/brief serializer for SoftwareLCM."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:nautobot_device_lifecycle_mgmt-api:softwarelcm-detail"
    )

    class Meta:
        """Meta attributes."""

        model = models.SoftwareLCM
        fields = ["id", "url", "device_platform", "version", "end_of_support"]
        read_only_fields = ["device_platform"]


class NestedSoftwareImageLCMSerializer(WritableNestedSerializer):
    """Nested/brief serializer for SoftwareImageLCM."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:nautobot_device_lifecycle_mgmt-api:softwareimagelcm-detail"
    )

    class Meta:
        """Meta attributes."""

        model = models.SoftwareImageLCM
        fields = [
            "id",
            "url",
            "image_file_name",
            "device_types",
            "inventory_items",
            "object_tags",
            "download_url",
            "image_file_checksum",
            "default_image",
        ]


class NestedProviderLCMSerializer(WritableNestedSerializer):
    """Nested serializer for the provider class."""

    class Meta:
        """Meta magic method for the Provider nested serializer."""

        model = models.ProviderLCM
        fields = [
            "id",
            "name",
            "description",
            "physical_address",
            "phone",
            "email",
            "comments",
        ]


class NestedContractLCMSerializer(WritableNestedSerializer):
    """API serializer."""

    provider = NestedProviderLCMSerializer(many=False, read_only=False, required=True, help_text="Contract Provider")

    class Meta:
        """Meta attributes."""

        model = models.ContractLCM
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
        ]


class NestedCVELCMSerializer(WritableNestedSerializer):
    """Nested serializer for the CVE class."""

    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nautobot_device_lifecycle_mgmt-api:cvelcm-detail")

    class Meta:
        """Meta magic method for the CVE nested serializer."""

        model = models.CVELCM
        fields = [
            "id",
            "url",
            "display",
            "name",
            "published_date",
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
