"""Classification logic: malware vs pup/pua/adware/riskware.

Rules applied in priority order. First match wins.
"""


def classify(clamav: str = "", tags: str = "", misp_classification: str = "") -> str:
    """Classify a sample based on ClamAV signature, tags, and MISP type.

    Args:
        clamav: ClamAV detection name (e.g., "PUA.Win32.Adware.Foo")
        tags: Pipe-separated tags (e.g., "stealer|adware|packed")
        misp_classification: Classification from MISP Galaxy (e.g., "adware")

    Returns:
        One of: "malware", "pup", "pua", "adware", "riskware"
    """
    clamav_lower = clamav.lower()
    tags_lower = tags.lower()
    tag_set = set(tags_lower.split("|")) if tags_lower else set()

    if clamav_lower.startswith("pua."):
        return "pua"
    if clamav_lower.startswith("adware."):
        return "adware"
    if "adware" in tag_set:
        return "adware"
    if "pup" in tag_set:
        return "pup"
    if "pua" in tag_set:
        return "pua"
    if "riskware" in tag_set:
        return "riskware"
    if "bundler" in tag_set:
        return "pua"
    if misp_classification and misp_classification.lower() in ("adware", "pup", "pua", "riskware"):
        return misp_classification.lower()
    return "malware"
