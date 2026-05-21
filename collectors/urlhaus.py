"""Collector for URLhaus (abuse.ch) — payload hashes linked to malicious URLs."""

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
        """Extract hostname from a URL."""
        try:
            return urlparse(url).hostname or ""
        except Exception:
            return ""

    def collect(self):
        api_key = self.get_api_key(ENV_VAR)
        self.session.headers["Auth-Key"] = api_key

        seen = set()
        rows = []

        # 1. Recent payloads with linked URLs
        print("    Fetching recent payloads...")
        try:
            resp = self.session.get(PAYLOADS_URL, timeout=60)
            resp.raise_for_status()
            result = resp.json()
            print(f"    Payloads response keys: {list(result.keys())[:5]}")
            payloads_list = result.get("payloads", [])
            print(f"    Payloads count: {len(payloads_list)}")
            if payloads_list:
                first = payloads_list[0]
                print(f"    First payload keys: {list(first.keys())}")
                print(f"    First payload urls key type: {type(first.get('urls'))}")
                print(f"    sha256_hash present: {'sha256_hash' in first}")
            for payload in payloads_list:
                sha256 = payload.get("sha256_hash", "")
                md5 = payload.get("md5_hash", "")
                for url_entry in payload.get("urls", []):
                    url = url_entry.get("url", "")
                    key = (sha256, url)
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append({
                        "sha256": sha256,
                        "md5": md5,
                        "url": url,
                        "host": self._extract_host(url),
                        "url_status": url_entry.get("url_status", ""),
                        "file_type": payload.get("file_type", ""),
                        "signature": payload.get("signature") or "",
                        "tags": "",
                        "first_seen": payload.get("firstseen", ""),
                    })
        except Exception as e:
            print(f"    Payloads fetch failed: {e}")

        # 2. Recent URLs with payload hashes
        print("    Fetching recent URLs...")
        try:
            resp = self.session.get(URLS_URL, timeout=60)
            resp.raise_for_status()
            result = resp.json()
            print(f"    URLs response keys: {list(result.keys())[:5]}")
            urls_list = result.get("urls", [])
            print(f"    URLs count: {len(urls_list)}")
            if urls_list:
                first = urls_list[0]
                print(f"    First URL keys: {list(first.keys())}")
                print(f"    First URL payloads type: {type(first.get('payloads'))}")
            for url_entry in urls_list:
                url = url_entry.get("url", "")
                host = url_entry.get("host", "") or self._extract_host(url)
                tags_list = url_entry.get("tags") or []
                tags = "|".join(tags_list) if isinstance(tags_list, list) else str(tags_list)
                for payload in url_entry.get("payloads", []):
                    sha256 = payload.get("sha256_hash", "")
                    key = (sha256, url)
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append({
                        "sha256": sha256,
                        "md5": payload.get("md5_hash", ""),
                        "url": url,
                        "host": host,
                        "url_status": url_entry.get("url_status", ""),
                        "file_type": payload.get("file_type", ""),
                        "signature": payload.get("signature") or "",
                        "tags": tags,
                        "first_seen": url_entry.get("dateadded", ""),
                    })
        except Exception as e:
            print(f"    URLs fetch failed: {e}")

        print(f"    Total URL-hash pairs: {len(rows)}")
        return rows
