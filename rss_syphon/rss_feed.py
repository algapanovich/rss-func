# rss_syphon/rss_feed.py

from dotenv import load_dotenv
load_dotenv()

# --- START: CORRECTED CONFIGURATION LOADING ---
import os
import importlib
from rss_config import slack_params_dict
from slacker.slacker import send_message
from rss_syphon.state import get_state

import logging
logger = logging.getLogger(__name__)

# Get the config module name from an environment variable, defaulting to 'rss_data'
config_module_name = os.getenv("SYPHON_CONFIG_MODULE", "rss_data")
logger.info(f"Loading configuration from module: {config_module_name}")
# Namespace for persisted state, so separate deployments never share it
DEPLOYMENT = os.getenv("SYPHON_DEPLOYMENT", config_module_name)
# Rolling window instead of "today only": survives missed runs and timezone edges
LOOKBACK_HOURS = int(os.getenv("LOOKBACK_HOURS", "36"))
try:
    config = importlib.import_module(config_module_name)
    # Use the data from the dynamically loaded config file
    rss_feed_list = config.rss_feed_list
    keywords_data = config.keywords
except ImportError:
    logger.critical(f"FATAL: Could not import configuration module '{config_module_name}'. Please ensure the file '{config_module_name}.py' exists.")
    exit(1) # Exit if the config can't be found
# --- END: CORRECTED CONFIGURATION LOADING ---


import re
import sys
import feedparser
import hashlib
import asyncio
import aiohttp
from time import mktime
from datetime import datetime, timedelta, timezone

NOT_MODIFIED = {"entries": [], "not_modified": True}


async def fetch(sem, session, feed_name, feed_url, validators, new_validators):
    """
    Fetch one feed. Sends If-None-Match / If-Modified-Since when known and
    records fresh validators in new_validators (committed only after a
    successful run, so a failed post is retried with the full feed).
    """
    req_headers = {}
    if validators.get("etag"):
        req_headers["If-None-Match"] = validators["etag"]
    if validators.get("last_modified"):
        req_headers["If-Modified-Since"] = validators["last_modified"]
    try:
        async with sem, session.get(
            feed_url, headers=req_headers, timeout=aiohttp.ClientTimeout(total=30)
        ) as response:
            if response.status == 304:
                return NOT_MODIFIED, feed_name
            if response.status == 200:
                data = await response.text()
                new_validators[feed_url] = {
                    "etag": response.headers.get("ETag"),
                    "last_modified": response.headers.get("Last-Modified"),
                }
                stripped = "\n".join([line.rstrip() for line in data.splitlines() if line.strip()])
                return feedparser.parse(stripped), feed_name
            msg = f"Error: API call Failed for {feed_name} => {response.status} : {response.reason}"
            logger.error(msg)
            return msg, feed_name
    except Exception as e:
        msg = f"Error during fetch for {feed_name}: {type(e).__name__}: {e}"
        logger.error(msg)
        return msg, feed_name


async def fetch_all(feeds_list, state, new_validators):
    """
    Takes a list of feeds and manages the fetch calls using async functions
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0'
    }
    sem = asyncio.Semaphore(10)
    async with aiohttp.ClientSession(headers=headers, max_field_size=32768) as session:
        return await asyncio.gather(
            *[
                fetch(sem, session, f["name"], f["url"],
                      state.get_validators(f["url"]) if state else {}, new_validators)
                for f in feeds_list
            ],
            return_exceptions=True,
        )


def fetch_feed_results(feeds_list, state=None, new_validators=None):
    """
    Fetch RSS feed data using async functions
    """
    if new_validators is None:
        new_validators = {}
    return asyncio.run(fetch_all(tuple(feeds_list), state, new_validators))


def process_feeds(feed_results, feeds_list=None):
    """
    Clean up data being passed back to the calling
    function and handle any exceptions that were thrown.
    """
    processed_results = []
    for result in feed_results:
        if isinstance(result, Exception):
            logger.error(f"An exception occurred during the fetch process: {result}")
            continue
        if not isinstance(result, tuple) or len(result) != 2:
            logger.warning(f"Received an unexpected result format, skipping: {result}")
            continue

        feed_data, feed_name = result
        # Successful fetches return a feedparser object, any string is an error message
        if isinstance(feed_data, str):
            error_entry = {"entries": None, "message": {"feed_name": feed_name, "error": feed_data}}
            processed_results.append((error_entry, feed_name))
        else:
            processed_results.append(result)
    return processed_results


def compile_keywords(keywords_list):
    """
    Compile every keyword once. '+' in a keyword is a single-character wildcard.
    Returns a list of (keyword, compiled_pattern).
    """
    compiled = []
    for kw in dict.fromkeys(k.strip() for k in keywords_list if k and k.strip()):
        pattern = re.escape(kw).replace(r"\+", ".")
        compiled.append((kw, re.compile(rf"(?<!\w){pattern}(?!\w)", re.IGNORECASE)))
    return compiled


def compile_ignored(ignore_list):
    """One combined pattern for the ignore list, or None when it is empty."""
    words = [re.escape(w) for w in ignore_list if w]
    if not words:
        return None
    return re.compile(r"\b(?:" + "|".join(words) + r")\b", re.IGNORECASE)


def article_uid(item):
    """Stable identity of an entry: GUID, else link, else title."""
    raw = item.get("id") or item.get("link") or item.get("title") or ""
    return hashlib.sha256(str(raw).encode("utf-8")).hexdigest()


def entry_datetime(item):
    """Entry timestamp as an aware UTC datetime, or None if the feed gives none."""
    for field in ("published_parsed", "updated_parsed"):
        parsed = item.get(field)
        if parsed:
            # feedparser *_parsed values are UTC struct_times
            try:
                return datetime.fromtimestamp(timegm_utc(parsed), tz=timezone.utc)
            except (ValueError, OverflowError, OSError):
                continue  # garbage timestamp (e.g. year 0), try the next field
    return None


def timegm_utc(struct):
    import calendar
    return calendar.timegm(struct)


def prepare_feed_message(rss_feeds, patterns, ignore_re=None, lookback_hours=None,
                         seen=None, now=None):
    """
    Select entries inside the lookback window that match keywords and have not
    been seen before. `patterns` comes from compile_keywords, `ignore_re` from
    compile_ignored, `seen` is a callable uid -> bool.
    """
    lookback_hours = LOOKBACK_HOURS if lookback_hours is None else lookback_hours
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=lookback_hours)
    feed_errors, date_errors, old_articles = [], [], []
    matched = {"titles": [], "articles": [], "keywords": {}}
    uids = set()

    for rss_feed, rss_feed_name in rss_feeds:
        if rss_feed.get("entries") is None:
            feed_errors.append(rss_feed_name)
            continue
        for item in rss_feed["entries"]:
            try:
                item_date = entry_datetime(item)
                if item_date is None:
                    date_errors.append(rss_feed_name)
                    continue
                if item_date < cutoff:
                    old_articles.append(f"{item_date:%Y-%m-%d} - {rss_feed_name} - {item.get('title', 'No Title')}")
                    continue
                uid = article_uid(item)
                if uid in uids or (seen and seen(uid)):
                    continue
                article = search_keywords(item, patterns, ignore_re, rss_feed_name)
                if article:
                    article["uid"] = uid
                    uids.add(uid)
                    matched["articles"].append(article)
                    for kw in article["keywords"]:
                        matched["keywords"][kw] = matched["keywords"].get(kw, 0) + 1
            except (KeyError, TypeError, ValueError) as e:
                logger.error(f"Error processing item in {rss_feed_name}: {e}")
                feed_errors.append(rss_feed_name)
    return matched, feed_errors, date_errors, old_articles


def search_keywords(rss_post, patterns, ignore_re, rss_feed_name):
    """
    Match one post against precompiled keyword patterns.
    Returns the article dict (with keywords and md5) or None.
    """
    post_content = f"{rss_post.get('title', '')} {rss_post.get('summary', '')}"
    if ignore_re and ignore_re.search(post_content):
        return None
    found = [kw for kw, pat in patterns if pat.search(post_content)]
    if not found:
        return None
    article = dict(rss_post)
    article["rss_feed_name"] = rss_feed_name
    article["keywords"] = found
    # md5 of the title is kept because existing Slack messages carry it
    article["md5"] = hashlib.md5(str(rss_post.get("title", "No Title")).encode("utf-8")).hexdigest()
    return article


def check_last_modified(date, days=365):
    """
    Return the date string if it is older than `days`, else None.
    """
    try:
        last_modified = datetime.strptime(date, "%Y-%m-%d")
        if (datetime.now() - last_modified).days > days:
            return date
    except (ValueError, TypeError):
        return None
    return None


def run_job(job_type):
    """
    Executes the full fetch, process, and send pipeline for a given job type.
    Returns True on success (or when there was nothing to post), False on failure.
    """
    logger.info(f"--- Starting Job: {job_type.upper()} (deployment {DEPLOYMENT}) ---")

    feeds_list = rss_feed_list[job_type]
    keywords = keywords_data["static_keywords"]
    patterns = compile_keywords(keywords)
    ignore_re = compile_ignored(keywords_data["ignored"])
    stale_keywords_date = check_last_modified(keywords_data.get("last_modified"), days=90)

    state = get_state(DEPLOYMENT, job_type)
    new_validators = {}

    logger.info(f"Fetching {len(feeds_list)} feeds for job type '{job_type}'")
    results = fetch_feed_results(feeds_list, state, new_validators)
    processed = process_feeds(results, feeds_list)

    matched, feed_errors, date_errors, old_articles = prepare_feed_message(
        processed, patterns, ignore_re, seen=state.is_seen
    )
    logger.info(f"New matched articles for {job_type}: {len(matched['articles'])}")
    for article in matched["articles"]:
        logger.info(f"  - {article.get('title', 'No Title')}")

    sent = send_message(
        job_type=job_type,
        message_params=slack_params_dict,
        matched=matched,
        errors=feed_errors,
        check_stale_keywords=stale_keywords_date,
    )

    if sent is True:
        # Only advance state after Slack accepted the posts, so a retry never loses articles
        state.mark_seen(a["uid"] for a in matched["articles"])
        for url, v in new_validators.items():
            state.set_validators(url, v.get("etag"), v.get("last_modified"))
        try:
            state.save()
        except Exception as e:
            logger.error(f"Could not save state: {e}")
            return False
    logger.info(f"--- Finished Job: {job_type.upper()} ---")
    return sent is not False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s: %(message)s")
    logger.info("Starting the RSS syphon script")

    ok = True
    for current_job in ["cve", "news"]:
        try:
            ok = run_job(current_job) and ok
        except Exception:
            logger.exception(f"Job {current_job} crashed")
            ok = False

    logger.info("All jobs complete." if ok else "Finished with failures.")
    # Non-zero exit makes Cloud Run mark the execution failed (and retry / alert)
    sys.exit(0 if ok else 1)
