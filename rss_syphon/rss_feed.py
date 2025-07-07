
from dotenv import load_dotenv
load_dotenv()
from rss_config import slack_params_dict
from slacker.slacker import send_message
from rss_data import rss_feed_list, keywords as keywords_data


import logging
import re
import feedparser
import hashlib
import asyncio
import aiohttp
from aiohttp import ClientConnectorError, ClientError
from time import mktime
from datetime import datetime

logger = logging.getLogger(__name__)


async def fetch(sem, session, feed_name, feed_url):
    """
    Fetch RSS results using passed in feed URLs
    """
    try:
        async with sem, session.get(feed_url, timeout=30) as response:
            if response.status == 200:
                data = await response.text()
                stripped = "\n".join([line.rstrip() for line in data.splitlines() if line.strip()])
                rss_page = feedparser.parse(stripped)
                return rss_page, feed_name
            else:
                msg = f"Error: API call Failed for {feed_name} => {response.status} : {response.reason}"
                logger.error(msg)
                return msg, feed_name
    except Exception as e:
        msg = f"Error during fetch for {feed_name}: {e}"
        logger.error(msg)
        return msg, feed_name

def get_or_create_event_loop():
    """
    Handles python 3.10+ deprecation of get_event_loop() when no loop is running
    """
    try:
        return asyncio.get_event_loop()
    except RuntimeError as ex:
        if "There is no current event loop in thread" in str(ex):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return asyncio.get_event_loop()

async def fetch_all(feeds_list, loop):
    """
    Takes a list of urls and manages the fetch calls using async functions
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0'
    }
    sem = asyncio.Semaphore(10)
    async with aiohttp.ClientSession(loop=loop, headers=headers) as session:
        fetch_res = await asyncio.gather(
            *[fetch(sem, session, feed["name"], feed["url"]) for feed in feeds_list], return_exceptions=True
        )
        return fetch_res

def fetch_feed_results(feeds_list):
    """
    Fetch RSS feed data using async functions
    """
    loop = get_or_create_event_loop()
    fetched_res = loop.run_until_complete(fetch_all(tuple(feeds_list), loop))
    return fetched_res

def process_feeds(feed_results, feeds_list):
    """
    Clean up data being passed back to the calling
    function and handle any exceptions that were thrown.
    """
    processed_results = []
    for result in feed_results:
        # Case 1: An exception was caught by asyncio.gather (timeout, connection error)
        if isinstance(result, Exception):
            logger.error(f"An exception occurred during the fetch process: {result}")
            continue

        # Check if the result is a tuple as expected from our fetch function
        if not isinstance(result, tuple) or len(result) != 2:
            logger.warning(f"Received an unexpected result format, skipping: {result}")
            continue

        feed_data, feed_name = result

         # Case 2: Check if the fetched data is ANY string. Since successful fetches
        # return a feedparser object, any string indicates an error message.
        if isinstance(feed_data, str):
           
            error_entry = {"entries": None, "message": {"feed_name": feed_name, "error": feed_data}}
            processed_results.append((error_entry, feed_name))
        
        # Case 3: A successful result from the fetch function
        else:
            processed_results.append(result)

    return processed_results


def prepare_feed_message(rss_feeds, keywords_list, ignored_list, hard_ignore=False):
    """
    Prepare returned RSS feed posts by checking entries and datetime values.
    """
    feed_errors = []
    date_errors = []
    old_articles = []
    matched = {"titles": [], "articles": [], "keywords": {}}
    for rss_feed, rss_feed_name in rss_feeds:
        # Check for our custom error structure or if entries are missing
        if rss_feed.get("entries") is None:
            feed_errors.append(rss_feed_name)
            continue
        
        for item in rss_feed["entries"]:
            try:
                item_date = None
                if "published_parsed" in item and item.published_parsed:
                    item_date = datetime.fromtimestamp(mktime(item["published_parsed"]))
                elif "updated_parsed" in item and item.updated_parsed:
                    item_date = datetime.fromtimestamp(mktime(item["updated_parsed"]))
                else:
                    date_errors.append(rss_feed_name)
                    continue
                if datetime.now().date() == item_date.date():
                    kw_res = search_keywords(item, keywords_list, ignored_list, rss_feed_name, hard_ignore)
                    if kw_res["articles"]:
                        for article in kw_res["articles"]:
                            if article["md5"] not in [a["md5"] for a in matched["articles"]]:
                                matched["articles"].append(article)
                        if kw_res["keywords"]:
                            for kw, count in kw_res["keywords"].items():
                                matched["keywords"][kw] = matched["keywords"].get(kw, 0) + count
                else:
                    old_articles.append(f"{item_date.strftime('%Y-%m-%d')} - {rss_feed_name} - {item.get('title', 'No Title')}")
            except (KeyError, TypeError, ValueError) as e:
                logger.error(f"Error processing item in {rss_feed_name}: {e}")
                feed_errors.append(rss_feed_name)
    return matched, feed_errors, date_errors, old_articles

def check_ignored_keywords(rss_post, ignore_list):
    """
    Checks for any occurrence of any ignored word in the RSS post.
    """
    for ignored in ignore_list:
        if re.search(f"\\b{ignored}\\b", str(rss_post), re.IGNORECASE):
            return True
    return False

def search_keywords(rss_post, keywords_list, ignored_list, rss_feed_name, hard_ignore=False):
    """
    Search RSS posts using a list of keywords.
    """
    matched = {"titles": [], "articles": [], "keywords": {}}
    post_content = f"{rss_post.get('title', '')} {rss_post.get('summary', '')}".lower()
    if hard_ignore and check_ignored_keywords(post_content, ignored_list):
        return matched
    found_keywords_in_post = []
    for keyword in keywords_list:
        if re.search(f"\\b{keyword.replace('+', r'.')}\\b", post_content, re.IGNORECASE):
             found_keywords_in_post.append(keyword)
    if found_keywords_in_post:
        post_title = rss_post.get("title", "No Title")
        article_data = rss_post.copy()
        article_data['rss_feed_name'] = rss_feed_name
        article_data["keywords"] = found_keywords_in_post
        article_data["md5"] = hashlib.md5(str(post_title).encode('utf-8')).hexdigest()
        matched["articles"].append(article_data)
        for kw in found_keywords_in_post:
            matched["keywords"][kw] = matched["keywords"].get(kw, 0) + 1
    return matched

def check_last_modified(date, days=365):
    """
    Check if date delta is within a certain amount of days.
    """
    try:
        last_modified = datetime.strptime(date, "%Y-%m-%d")
        delta = datetime.now() - last_modified
        if delta.days > days:
            return date
    except (ValueError, TypeError):
        return None
    return None

def run_job(job_type):
    """
    Executes the full fetch, process, and send pipeline for a given job type.
    """
    logger.info(f"--- Starting Job: {job_type.upper()} ---")

    # Select the correct list of feeds and keywords based on the job
    feeds_list = rss_feed_list[job_type]
    keywords = keywords_data["static_keywords"]
    ignore = keywords_data["ignored"]
    stale_keywords_date = check_last_modified(keywords_data.get("last_modified"), days=90)

    # Fetch and process feeds
    logger.info(f"📡 Fetching {len(feeds_list)} feeds for job type: '{job_type}'...")
    results = fetch_feed_results(feeds_list)
    logger.info(f"✅ Fetch complete for {job_type}. Received {len(results)} results.")

    logger.info("🛠️ Processing feed results...")
    processed = process_feeds(results, feeds_list)
    logger.info(f"🧼 Processed feed results.")

    # Search for keywords in today's articles
    logger.info(f"🔍 Searching for keywords: {keywords[:5]}... (first 5 of {len(keywords)})")
    matched, feed_errors, date_errors, old_articles = prepare_feed_message(processed, keywords, ignore)
    
    # Log the results
    logger.info(f"📰 Matched articles for {job_type}: {len(matched['articles'])}")
    if not matched["articles"]:
        logger.info("No articles matched your keywords today.")
    else:
        for article in matched["articles"]:
            logger.info(f"  - {article.get('title', 'No Title')}")

    # SEND THE SLACK NOTIFICATION
    logger.info("📦 Preparing to send notifications to Slack...")
    send_message(
        job_type=job_type,
        message_params=slack_params_dict,
        matched=matched,
        errors=feed_errors,
        check_stale_keywords=stale_keywords_date
    )
    logger.info(f"--- Finished Job: {job_type.upper()} ---")


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s: %(message)s")
    logger.info("🚀 Starting the RSS syphon script...")
    
    # --- DEFINE AND RUN ALL JOBS SEQUENTIALLY ---
    JOBS_TO_RUN = ["cve", "news"]
    
    for current_job in JOBS_TO_RUN:
        run_job(current_job)

    logger.info("✅ All jobs complete.")