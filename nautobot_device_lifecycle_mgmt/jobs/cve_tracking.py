"""Jobs for the CVE Tracking portion of the Device Lifecycle plugin."""
from datetime import datetime, date
import json

from nautobot.extras.jobs import Job, StringVar
from nautobot.extras.models import Relationship, RelationshipAssociation

from nautobot_device_lifecycle_mgmt.models import (
    CVELCM,
    SoftwareLCM,
    VulnerabilityLCM,
)

import requests
import re
from time import sleep

name = "CVE Tracking"  # pylint: disable=invalid-name


class GenerateVulnerabilities(Job):
    """Generates VulnerabilityLCM objects based on CVEs that are related to Devices."""

    name = "Generate Vulnerabilities"
    description = "Generates any missing Vulnerability objects."
    read_only = False
    published_after = StringVar(
        regex=r"^[0-9]{4}\-[0-9]{2}\-[0-9]{2}$",
        label="CVEs Published After",
        description="Enter a date in ISO Format (YYYY-MM-DD) to only process CVEs published after that date.",
        default="1970-01-01",
        required=False,
    )

    class Meta:  # pylint: disable=too-few-public-methods
        """Meta class for the job."""

        commit_default = True

    def run(self, data, commit):  # pylint: disable=too-many-locals
        """Check if software assigned to each device is valid. If no software is assigned return warning message."""
        # Although the default is set on the class attribute for the UI, it doesn't default for the API
        published_after = data.get("published_after", "1970-01-01")
        cves = CVELCM.objects.filter(published_date__gte=datetime.fromisoformat(published_after))
        count_before = VulnerabilityLCM.objects.count()

        for cve in cves:
            software_rels = RelationshipAssociation.objects.filter(relationship__slug="soft_cve", destination_id=cve.id)
            for soft_rel in software_rels:

                # Loop through any device relationships
                device_rels = soft_rel.source.get_relationships()["source"][
                    Relationship.objects.get(slug="device_soft")
                ]
                for dev_rel in device_rels:
                    vuln_obj, _ = VulnerabilityLCM.objects.get_or_create(
                        cve=cve, software=dev_rel.source, device=dev_rel.destination
                    )
                    vuln_obj.validated_save()

                # Loop through any inventory tem relationships
                item_rels = soft_rel.source.get_relationships()["source"][
                    Relationship.objects.get(slug="inventory_item_soft")
                ]
                for item_rel in item_rels:
                    vuln_obj, _ = VulnerabilityLCM.objects.get_or_create(
                        cve=cve, software=item_rel.source, inventory_item=item_rel.destination
                    )
                    vuln_obj.validated_save()

        diff = VulnerabilityLCM.objects.count() - count_before
        self.log_success(message=f"Processed {cves.count()} CVEs and generated {diff} Vulnerabilities.")


class NistCveSyncSoftware(Job):
    """Checks all software in the DLC Plugin for NIST recorded vulnerabilities."""

    name = "Find current NIST CVE for Software in Database"
    description = """Searches the NIST DBs for CVEs related to software"""
    read_only = False

    class Meta:  # pylint: disable=too-few-public-methods
        """Meta class for the job."""

        commit_default = True
        hidden = True

    def run(self, data, commit):
        """Check all software in DLC against NIST database and associate registered CVEs.  Update when necessary."""
        all_software = SoftwareLCM.objects.all()
        cve_counter = 0

        for software in all_software:
            manufacturer = str(software.device_platform.manufacturer).lower()
            platform = self.validate_platform_name(str(software.device_platform.name).lower())
            version = self.validate_platform_version(str(software.version))

            cpe_software_search_url = self.create_cpe_software_search_url(manufacturer, platform, version)
            software_cve_info = self.get_cve_info(cpe_software_search_url, software.id)

            cve_counter += len(software_cve_info)
            self.create_dlc_cves(software.id, software_cve_info)

        self.log_success(
            message=f"""Performed discovery on all software meeting
                        naming standards.  Added {cve_counter} CVE."""
        )
        self.update_cves()

    def validate_platform_name(self, platform: str) -> str:
        """Platform names are typically entered with a preceding manufacturername.

        Remove the preceding Manufacturer name and return only a platform
        by splitting on the first space and replace spaces with underscores to
        prepare.
        """
        platform = platform.split(" ", 1)[1].lower()
        platform = platform.replace(" ", "_")

        return platform

    def validate_platform_version(self, version: str) -> str:
        """Platform versions may contain characters that need to be escaped.

        Create a compatible version.
        If any additional chars need to be escaped, add to the list.
        """
        escape_list = [r"\(", r"\)"]
        for escape_char in escape_list:
            if re.search(escape_char, version):
                version = re.sub(escape_char, "\\" + escape_char, version)

        return version

    def create_cpe_software_search_url(self, manufacturer: str, platform: str, version: str) -> str:
        """Return the url for a cpe search against the NIST DB."""
        base_url = f"""https://services.nvd.nist.gov/rest/json/cpes/1.0?addOns=cves&cpeMatchString=cpe:2.3:*:"""
        extended_url = f"{manufacturer}:{platform}:{version}:*:*:*:*:*:*:*"

        return f"{base_url}{extended_url}"

    def prep_cve_for_dlc(self, url: str) -> dict:
        """Performs search of NIST CVE DB and prepares data for insertion to DLC Management Plugin."""
        cve_name = url.split("/")[-1]
        cve_search_url = f"{url}"
        result = json.loads(requests.get(cve_search_url).text)

        if result.get("message"):
            self.log_info(message=f"""CVE {cve_name} DOES NOT EXIST IN NIST DATABASE""")
            return

        cve_base = result["result"]["CVE_Items"][0]
        cve_description = cve_base["cve"]["description"]["description_data"][0]["value"]
        cve_published_date = cve_base.get("publishedDate")
        cve_modified_date = cve_base.get("lastModifiedDate")
        cve_impact = cve_base.get("impact")

        reference_data = result["result"]["CVE_Items"][0]["cve"]["references"]["reference_data"]
        if len(reference_data) > 0:
            cve_url = reference_data[0].get("url", f"https://www.cvedetails.com/cve/{cve_name}/")
        else:
            cve_url = f"https://www.cvedetails.com/cve/{cve_name}/"

        if cve_impact.get("baseMetricV3"):
            cvss_base_score = cve_impact["baseMetricV3"]["cvssV3"]["baseScore"]
            cvss_severity = cve_impact["baseMetricV3"]["cvssV3"]["baseSeverity"]
            cvssv2_score = cve_impact["baseMetricV2"]["exploitabilityScore"]
            cvssv3_score = cve_impact["baseMetricV3"]["exploitabilityScore"]
        else:
            cvss_base_score = cve_impact["baseMetricV2"]["cvssV2"]["baseScore"]
            cvss_severity = cve_impact["baseMetricV2"]["severity"]
            cvssv2_score = cve_impact["baseMetricV2"]["exploitabilityScore"]
            cvssv3_score = None

        all_cve_info = {
            "url": cve_url,
            "description": cve_description,
            "published_date": cve_published_date,
            "modified_date": cve_modified_date,
            "cvss_base_score": cvss_base_score,
            "cvss_severity": cvss_severity,
            "cvssv2_score": cvssv2_score,
            "cvssv3_score": cvssv3_score,
        }

        return all_cve_info

    def get_cve_info(self, cpe_software_search_url: str, software_id=None) -> dict:
        """Search NIST for software and related CVEs."""
        cpe_info = json.loads(requests.get(cpe_software_search_url).text)
        all_cve_info = {}
        if len(cpe_info["result"]["cpes"]) > 0:
            cve_list = cpe_info["result"]["cpes"][0].get("vulnerabilities", [])
            base_url = "https://services.nvd.nist.gov/rest/json/cve/1.0/"

            dlc_cves = [cve["name"] for cve in CVELCM.objects.values("name")]

            for cve in cve_list:
                if cve not in dlc_cves and cve.startswith("CVE"):
                    all_cve_info[cve] = self.prep_cve_for_dlc(base_url + cve)
                    sleep(0.25)
                else:
                    existing_cve = CVELCM.objects.get(name=cve)
                    self.associate_software_to_cve(software_id, existing_cve.id)

        return all_cve_info

    def create_dlc_cves(self, software_id, cpe_cves):
        """Create the list of items that will need to be inserted to DLC CVEs."""
        dlc_cves = CVELCM.objects.all()
        for cve, info in cpe_cves.items():
            if cve not in dlc_cves:
                dlc_cve, created = CVELCM.objects.get_or_create(
                    name=cve,
                    defaults={
                        "description": (
                            f'{result["description"][0:251]}...'
                            if len(result["description"]) > 255
                            else result["description"]
                        ),
                        "published_date": date.fromisoformat(info["published_date"][0:10]),
                        "last_modified_date": date.fromisoformat(info["modified_date"][0:10]),
                        "link": info["url"],
                        "cvss": info["cvss_base_score"],
                        "severity": info["cvss_severity"],
                        "cvss_v2": info["cvssv2_score"],
                        "cvss_v3": info["cvssv3_score"],
                        "comments": "ENTRY CREATED BY NAUTOBOT NIST JOB",
                    },
                )

                self.log_info(message=f"""Created {cve}""")
                self.associate_software_to_cve(software_id, dlc_cve.id)

            else:
                cve = CVELCM.objects.get(name=cve)
                self.associate_software_to_cve(software_id, cve)

    def associate_software_to_cve(self, software_id, cve):
        """A method to associate the software to the CVE."""
        r_type = Relationship.objects.get(slug="soft_cve")
        RelationshipAssociation.objects.get_or_create(
            relationship_id=r_type.id,
            source_type_id=r_type.source_type_id,
            source_id=software_id,
            destination_type_id=r_type.destination_type_id,
            destination_id=cve,
        )

    def update_cves(self):
        """A method to ensure the CVE in DLC is the latest version."""
        self.log_info(message=f"""Checking for CVE Modifications""")
        base_url = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
        dlc_cves = CVELCM.objects.all()

        for cve in dlc_cves:
            try:
                result = self.prep_cve_for_dlc(base_url + cve.name)

                if str(result.get("modified_date")[0:10]) != str(cve.last_modified_date):
                    cve.description = (
                        f'{result["description"][0:251]}...'
                        if len(result["description"]) > 255
                        else result["description"]
                    )
                    cve.last_modified_date = f'{result.get("modified_date")[0:10]}'
                    cve.link = result["url"]
                    cve.cvss = result["cvss_base_score"]
                    cve.severity = result["cvss_severity"]
                    cve.cvss_v2 = result["cvssv2_score"]
                    cve.cvss_v3 = result["cvssv3_score"]
                    cve.comments = "ENTRY UPDATED BY NAUTOBOT NIST JOB"

                    try:
                        cve.validated_save()
                        self.log_info(message=f"""{cve.name} was modified.""")

                    except:
                        self.log_info(message=f"""Unable to update {cve.name}.""")
                        pass

            except:
                self.log_info(message=f"""CVE CHECK FAILED FOR THIS CVE.  RERUN JOB.""")
                pass

        self.log_success(message=f"""All CVE's requiring modifications have been updated.""")
