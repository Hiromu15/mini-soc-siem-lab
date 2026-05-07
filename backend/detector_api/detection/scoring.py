SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


def severity_score(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.lower(), 0)

