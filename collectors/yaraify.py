"""Collector for YARAify (abuse.ch) deployed YARA rules with family mappings."""

from collectors.base import BaseCollector

API_URL = "https://yaraify-api.abuse.ch/api/v1/"
ENV_VAR = "YARAIFY_API_KEY"


class YARAifyCollector(BaseCollector):
    @property
    def source_name(self):
        return "yaraify_rules"

    @property
    def fieldnames(self):
        return [
            "rule_name", "author", "description", "malpedia_family",
            "matching_tlp", "sharing_tlp", "yarahub_uuid", "date",
        ]

    def collect(self):
        api_key = self.get_api_key(ENV_VAR)
        self.session.headers["Auth-Key"] = api_key

        resp = self.session.post(API_URL, data={"query": "recent_yararules"})
        resp.raise_for_status()
        result = resp.json()

        if result.get("query_status") != "ok":
            print(f"  YARAify query_status: {result.get('query_status')}")
            return []

        rows = []
        for rule in result.get("data", []):
            rows.append({
                "rule_name": rule.get("rule_name", ""),
                "author": rule.get("author", ""),
                "description": rule.get("description", ""),
                "malpedia_family": rule.get("malpedia_family", ""),
                "matching_tlp": rule.get("yarahub_rule_matching_tlp", ""),
                "sharing_tlp": rule.get("yarahub_rule_sharing_tlp", ""),
                "yarahub_uuid": rule.get("yarahub_uuid", ""),
                "date": rule.get("date", ""),
            })

        return rows
