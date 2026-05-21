"""Collector for AlienVault OTX — subscribed pulse indicators."""

from collectors.base import BaseCollector

API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
ENV_VAR = "OTX_API_KEY"

RELEVANT_TYPES = {"FileHash-SHA256", "FileHash-MD5", "IPv4", "domain", "URL", "hostname"}


class OTXCollector(BaseCollector):
    @property
    def source_name(self):
        return "otx_pulses"

    @property
    def fieldnames(self):
        return [
            "ioc_type", "ioc_value", "family", "pulse_name",
            "pulse_id", "created", "tags",
        ]

    def collect(self):
        api_key = self.get_api_key(ENV_VAR)
        self.session.headers["X-OTX-API-KEY"] = api_key

        rows = []
        page = 1
        max_pages = 20

        while page <= max_pages:
            print(f"    Fetching OTX pulses page {page}...")
            try:
                resp = self.session.get(
                    API_URL,
                    params={"limit": 50, "page": page},
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                print(f"    OTX page {page} failed: {e}")
                break

            pulses = data.get("results", [])
            if not pulses:
                break

            for pulse in pulses:
                pulse_id = pulse.get("id", "")
                pulse_name = pulse.get("name", "")
                created = pulse.get("created", "")
                tags_list = pulse.get("tags", [])
                tags = "|".join(tags_list) if isinstance(tags_list, list) else ""

                families = pulse.get("malware_families", [])
                family = ""
                if isinstance(families, list) and families:
                    first = families[0]
                    if isinstance(first, dict):
                        family = first.get("display_name", "")
                    elif isinstance(first, str):
                        family = first

                for indicator in pulse.get("indicators", []):
                    ioc_type = indicator.get("type", "")
                    if ioc_type not in RELEVANT_TYPES:
                        continue
                    rows.append({
                        "ioc_type": ioc_type,
                        "ioc_value": indicator.get("indicator", ""),
                        "family": family,
                        "pulse_name": pulse_name,
                        "pulse_id": pulse_id,
                        "created": created,
                        "tags": tags,
                    })

            if not data.get("next"):
                break
            page += 1

        print(f"    Total OTX indicators: {len(rows)}")
        return rows
