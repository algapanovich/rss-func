RSS-Syphon
RSS-Syphon is an XML feed scraper that allows searching through returned RSS posts with customizable keywords.
Run this as a daily vulnerability intel job to provide general awareness based on relevant topics.

RSS-Syphon supports ingesting multiple RSS feeds for jobs geared towards security news or CVEs.
Results can be sent to a number of different places including Slack, Zendesk, and Notion.

RSS-Syphon also supports getting dynamic keywords from a Splunk search if needed.

Features
Fetch and parse multiple RSS feeds asynchronously
Keyword-based filtering with support for ignored terms
Lookback support to process older articles on new deployments
Integration with Slack, Notion, and Zendesk outputs
Dynamic keyword ingestion from Splunk queries
Robust error handling and logging
Modular outputs expansion supported
Requirements
Python 3.10+
Dependencies (install via pip install -r requirements.txt):
aiohttp
feedparser
beautifulsoup4
requests
slack_sdk (if Slack integration is used)
other dependencies as listed in requirements.txt
Access and credentials for output platforms you intend to use (Slack, Zendesk, Notion)
Optional: Splunk access for dynamic keyword fetching
Setup
Clone the repository
Create and activate a Python virtual environment
Install dependencies via pip install -r requirements.txt
Configure your .env file with credentials and API keys for Slack, Notion, Zendesk, Splunk, etc.
Customize rss_data.py to adjust keywords, RSS feed lists, and other config options
Configuration
RSS Feeds: Edit feeds.py (shared by all deployments) to add or modify RSS feed URLs and names under rss_feed_list. Feeds are organized by job types, e.g., "news" or "cve".
Keywords: each deployment has its own module (rss_data.py for the team, rss_data_vsa.py for privacy), selected with SYPHON_CONFIG_MODULE.
Outputs: Update rss_config.py with parameters for Slack, Notion, and Zendesk API connections.
Usage
Run daily to fetch and process RSS feeds:

python -m rss_syphon.rss_feed
You can also run inside Docker, passing your environment variables via an .env file:

  docker build -t rss-syphon .  
  docker run --env-file .env rss-syphon
Extending
Add or remove RSS feeds in rss_feed_list inside rss_data.py
Modify keyword lists in rss_data.py
Add new output modules by following the existing pattern in the src/ folder
Notes
Ensure network connectivity to RSS feed URLs
Use valid API keys and tokens for outputs
Lookback days parameter allows processing older articles when needed

State and deployments
Dedup state (seen articles, per-feed ETag/Last-Modified) is stored per deployment and job type.
  SYPHON_CONFIG_MODULE  data module with feeds and keywords (default rss_data)
  SYPHON_DEPLOYMENT     state namespace (default: the config module name), keep unique per deployment
  STATE_BACKEND         firestore (default), file, or memory
  STATE_COLLECTION      Firestore collection (default rss_syphon_state)
  LOOKBACK_HOURS        rolling window of article age to consider (default 36)
  SEEN_TTL_DAYS         how long seen articles are remembered (default 30)
State only advances after Slack accepts the posts, and the process exits non-zero on failure
so Cloud Run marks the execution failed.
Tests: pip install pytest && python -m pytest tests

CVE enrichment and alerts
CVE posts are enriched with CVSS (NVD), exploited-in-the-wild status (CISA KEV) and EPSS.
High/Critical CVSS or a KEV listing posts with a rotating-light headline and a red Slack attachment.
  NVD_API_KEY       optional, raises the NVD rate limit (recommended)
  NVD_MAX_LOOKUPS   uncached NVD lookups per run (default 25); results are cached in state
  ENRICH_ENABLED    set to false to turn enrichment off
All sources fail soft: the article is posted without the missing field.
