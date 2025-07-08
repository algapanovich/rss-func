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
Dependencies (install via pip install -r src/requirements.txt):
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
Install dependencies via pip install -r src/requirements.txt
Configure your .env file with credentials and API keys for Slack, Notion, Zendesk, Splunk, etc.
Customize src/rss_data.py to adjust keywords, RSS feed lists, and other config options
Configuration
RSS Feeds: Edit rss_data.py to add or modify RSS feed URLs and names under rss_feed_list. Feeds are organized by job types, e.g., "news" or "cve".
Keywords: Configure keywords in rss_data.py for both static and dynamic use.
Outputs: Update rss_config.py with parameters for Slack, Notion, and Zendesk API connections.
Usage
Run daily to fetch and process RSS feeds:

python src/rss_syphon.py
You can also run inside Docker, passing your environment variables via an .env file:

  docker build -t rss-syphon .  
  docker run --env-file .env rss-syphon
Extending
Add or remove RSS feeds in rss_feed_list inside src/rss_data.py
Modify keyword lists in src/rss_data.py
Add new output modules by following the existing pattern in the src/ folder
Notes
Ensure network connectivity to RSS feed URLs
Use valid API keys and tokens for outputs
Lookback days parameter allows processing older articles when needed
