"""Collector for URLhaus (abuse.ch) — malicious URLs and payload hashes.

The recent endpoints return flat lists:
- /payloads/recent/ gives hashes with signatures but no URLs
- /urls/recent/ gives URLs with hosts but no payload hashes

We collect both. The payloads give us hash→family mappings,
and the URLs give us malicious domain/host IOCs.
"""

from urllib.parse import urlparse

from collectors.base import BaseCollector

PAYLOADS_URL = "https://urlhaus-api.abuse.ch/v1/payloads/recent/limit/1000/"
URLS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"
ENV_VAR = "URLHAUS_API_KEY"


class URLhausCollector(BaseCollector):
    @property
    def source_name(self):
        return "urlhaus"

    @property
    def fieldnames(self):
        return [
            "sha256", "md5", "url", "host", "url_status",
            "file_type", "signature", "tags", "first_seen",
        ]

    def _extract_host(self, url):
        try:
            return urlparse(url).hostname or ""
        except Exception:
            return ""

    def collect(self):
        api_key = self.get_api_key(ENV_VAR)
        self.session.headers["Auth-Key"] = api_key

        rows = []

        # 1. Recent payloads — hashes with family signatures
        print("    Fetching recent payloads...")
        try:
            resp = self.session.get(PAYLOADS_URL, timeout=60)
            resp.raise_for_status()
            result = resp.json()
            payloads_list = result.get("payloads", [])
            print(f"    Got {len(payloads_list)} payloads")
            for payload in payloads_list:
                sha256 = payload.get("sha256_hash", "")
                if not sha256:
                    continue
                # urlhaus_download is a URL where the payload was hosted
                download_url = payload.get("urlhaus_download") or ""
                rows.append({
                    "sha256": sha256,
                    "md5": payload.get("md5_hash", ""),
                    "url": download_url,
                    "host": self._extract_host(download_url) if download_url else "",
                    "url_status": "",
                    "file_type": payload.get("file_type", ""),
                    "signature": payload.get("signature") or "",
                    "tags": "",
                    "first_seen": payload.get("firstseen", ""),
                })
        except Exception as e:
            print(f"    Payloads fetch failed: {e}")

        # 2. Recent URLs — malicious URLs with host info
        print("    Fetching recent URLs...")
        try:
            resp = self.session.get(URLS_URL, timeout=60)
            resp.raise_for_status()
            result = resp.json()
            urls_list = result.get("urls", [])
            print(f"    Got {len(urls_list)} URLs")
            for url_entry in urls_list:
                url = url_entry.get("url", "")
                if not url:
                    continue
                host = url_entry.get("host", "") or self._extract_host(url)
                tags_list = url_entry.get("tags") or []
                tags = "|".join(tags_list) if isinstance(tags_list, list) else str(tags_list)
                rows.append({
                    "sha256": "",  # URLs endpoint doesn't include payload hashes
                    "md5": "",
                    "url": url,
                    "host": host,
                    "url_status": url_entry.get("url_status", ""),
                    "file_type": "",
                    "signature": "",
                    "tags": tags,
                    "first_seen": url_entry.get("date_added", ""),
                })
        except Exception as e:
            print(f"    URLs fetch failed: {e}")

        print(f"    Total URLhaus entries: {len(rows)}")
        return rows
