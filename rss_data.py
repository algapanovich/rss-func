"""
# Team deployment keywords
Feeds are shared and live in feeds.py. Select this module with SYPHON_CONFIG_MODULE=rss_data (default).
Keywords contain ignored keywords and static keywords. Review periodically and bump last_modified.
"""
from feeds import rss_feed_list  # noqa: F401  (re-exported for rss_syphon.rss_feed)

keywords = {
    "last_modified": "2025-06-05",
    "ignored": [
        "hiring"
    ],
    "static_keywords": [
        "agi",
        "abnormal",
        "ai",
        "amazon",
        "apple",
        "atlassian",
        "aws",
        "chrome",
        "confluence",
        "crowdstrike",
        "docker",
        "docusign",
        "gcp",
        "gemini",
        "globalprotect",
        "google cloud",
        "google cloud platform",
        "google workspace",
        "healthcare",
        "infoblox",
        "ios",
        "jamf",
        "jamf pro",
        "jenkins",
        "jira",
        "keeper",
        "kubernetes",
        "lucid",
        "macbook",
        "macos",
        "malware",
        "okta",
        "ransomware",
        "slack",
        "zoom",
        "cloud armor",
        "hacker one",
        "h1",
        "panorama",
        "palo alto"
    ]
}
