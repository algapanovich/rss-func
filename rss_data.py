"""
# Team deployment keywords
Feeds are shared and live in feeds.py. Select this module with SYPHON_CONFIG_MODULE=rss_data (default).
Keywords contain ignored keywords and static keywords. Review periodically and bump last_modified.
"""
from feeds import rss_feed_list  # noqa: F401  (re-exported for rss_syphon.rss_feed)

keywords = {
    "last_modified": "2026-11-23",
    # Noise filter applied to title + summary
    "ignored": [
        "hiring",
        "webinar",
        "sponsored",
        "giveaway",
        "black friday",
        "cyber monday",
        "coupon",
    ],
    "static_keywords": [
        # --- Our stack: cloud and infrastructure ---
        "gcp",
        "google cloud",
        "gke",
        "cloud run",
        "cloud armor",
        "bigquery",
        "vertex ai",
        "workload identity",
        "kubernetes",
        "k8s",
        "container escape",
        "containerd",
        "runc",
        "docker",
        "terraform",
        "hashicorp",
        "aws",
        "neo4j",
        # --- Our stack: security tooling ---
        "crowdstrike",
        "falcon sensor",
        "wiz",
        "splunk",
        "tenable",
        "nessus",
        "hackerone",
        "hacker one",
        # --- Our stack: identity and SaaS ---
        "okta",
        "google workspace",
        "keeper security",
        "slack",
        "atlassian",
        "jira",
        "confluence",
        "notion",
        "zendesk",
        "zoom",
        "docusign",
        "lucidchart",
        "gemini",
        # --- Our stack: network and endpoint ---
        "palo alto",
        "pan-os",
        "panorama",
        "globalprotect",
        "infoblox",
        "jenkins",
        "github actions",
        "chrome",
        "chromium",
        "macos",
        "macbook",
        "ios",
        "iru",
        "kandji",  # Iru was formerly Kandji; older articles still use the name
        "mdm",
        # --- Industry ---
        "healthcare",
        "hipaa",
        # --- Trends: AI and agent security ---
        "ai agent",
        "agentic",
        "prompt injection",
        "mcp",
        "model context protocol",
        "llm",
        "jailbreak",
        # --- Trends: supply chain ---
        "supply chain attack",
        "npm",
        "pypi",
        "malicious package",
        "shai-hulud",
        # --- Trends: identity and SaaS attacks ---
        "oauth",
        "saml",
        "token theft",
        "session hijacking",
        "mfa bypass",
        "adversary-in-the-middle",
        "infostealer",
        "clickfix",
        "scattered spider",
        "shinyhunters",
        "help desk social engineering",
        # --- Trends: exploitation signals ---
        "actively exploited",
        "zero-day",
        "malware",
        "ransomware",
    ],
}
