"""
CVSS Risk Classification Module
"""


def classify_risk(cvss_score):
    """
    Classify CVSS score into severity levels.
    """

    if cvss_score is None:
        return "UNKNOWN", "white"

    score = float(cvss_score)

    if 0.0 <= score <= 3.9:
        return "LOW", "green"

    elif 4.0 <= score <= 6.9:
        return "MEDIUM", "yellow"

    elif 7.0 <= score <= 8.9:
        return "HIGH", "orange1"

    elif 9.0 <= score <= 10.0:
        return "CRITICAL", "red"

    return "UNKNOWN", "white"