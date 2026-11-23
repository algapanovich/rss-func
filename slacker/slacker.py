import logging
import re
from bs4 import BeautifulSoup
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import json
import time 


# Set module logger name
logger = logging.getLogger(__name__)

MAX_HISTORY_PAGES = 5


def init_slack_client(slack_token):
    """
    Instantiates a Slack web client that can call API methods

    :param slack_token: Slack API token
    :return: Slack Client Object
    """
    return WebClient(token=slack_token)


def read_channel(client, channel_id, rss_type):
    """
    Reads channel conversations and returns matching content

    This requires the following scopes:
      channels:history
      groups:history
      im:history
      mpim:history

    :param client: Slack Client Object
    :param channel_id: Slack Channel ID
    :param rss_type: CVE or NEWs job type
    :return: Dictionary of content
    """
    # Set default return dict
    re_dict = {
        "links": [],
        "md5s": [],
        "fixed_cves": [],
        "seen_cves": []
    }

    try:
        # Page through history (state store is the primary dedup, this is a safety net)
        conversation_history = []
        cursor = None
        for _ in range(MAX_HISTORY_PAGES):
            result = client.conversations_history(channel=channel_id, limit=200, cursor=cursor)
            conversation_history.extend(result["messages"])
            cursor = (result.get("response_metadata") or {}).get("next_cursor")
            if not cursor:
                break

        # Initialize dict and lists for storing links/md5s
        re_link = []
        link_regex = r"(?:link\:.+?)(https?:\/\/(?:www\.)?[-a-zA-Z-1-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*))"
        re_results = re.findall(link_regex, str(conversation_history), re.IGNORECASE)
        for re_result in re_results:
            if re_result not in re_link:
                re_link.append(re_result)

        re_md5 = []
        md5_regex = r"(?:md5:\s)([a-f0-9]{32})"
        re_results = re.findall(md5_regex, str(conversation_history), re.IGNORECASE)
        for re_result in re_results:
            if re_result not in re_md5:
                re_md5.append(re_result)

        already_fixed_list = []
        already_seen_list = []

        # Save timestamp if cve
        if rss_type == "cve":
            cve_regex = r"(CVE-20[0-9]{2}-\d+)"

            for dialog in conversation_history:
                if "reactions" in dialog:
                    if list(filter(lambda item: item['name'] == 'white_check_mark', dialog["reactions"])):
                        cve_dialog_results = re.findall(cve_regex, str(dialog), re.IGNORECASE)
                        for dialog_result in cve_dialog_results:
                            if dialog_result not in already_fixed_list:
                                already_fixed_list.append(dialog_result)

            cve_convo_results = re.findall(cve_regex, str(conversation_history), re.IGNORECASE)
            for convo_result in cve_convo_results:
                if convo_result not in already_seen_list:
                    already_seen_list.append(convo_result)

        re_dict = {
            "links": re_link,
            "md5s": re_md5,
            "fixed_cves": already_fixed_list,
            "seen_cves": already_seen_list
        }

    except SlackApiError as e:
        msg = f"Error reading channel history: {e}"
        logger.error(msg)

    return re_dict


ALARM_COLOR = "#D50000"  # red attachment bar for High / Critical / KEV items


def _post_kwargs(item):
    """chat.postMessage arguments for one item {"headline","body","alarm"}."""
    if item.get("alarm"):
        # Headline stays in the message text (drives notifications), body goes
        # into a red attachment so the whole post is visibly flagged.
        return {
            "text": item["headline"],
            "attachments": [{
                "color": ALARM_COLOR,
                "text": item["body"],
                "fallback": item["headline"],
                "mrkdwn_in": ["text"],
            }],
        }
    return {"text": f"{item['headline']}\n{item['body']}".strip()}


def post_message(client, channel_id, messages):
    """
    This requires the following scopes:
      chat:write:bot
        Send messages as @syphon

    :param client: Slack Client Object
    :param channel_id: Slack Channel ID
    :param messages: list of {"headline","body","alarm"} items, or a plain string
    :return: True if every message was posted
    """
    if isinstance(messages, str):
        messages = [{"headline": m.strip(), "body": "", "alarm": False}
                    for m in messages.split('---EOM---') if m.strip()]
    all_ok = True
    for item in messages:
        try:
            result = client.chat_postMessage(
                channel=channel_id,
                unfurl_links=False,
                unfurl_media=False,
                parse="mrkdwn",
                **_post_kwargs(item),
            )
            logger.debug(result)
            time.sleep(1)
        except SlackApiError as e:
            all_ok = False
            logger.error(f"Error posting message: {e}")
    return all_ok


def clean_html(input_text):
    """
    Summaries often come as html formatted.
    This def uses bs4 to clean that up.

    :param input_text: Text to clean
    :return: Cleaned output
    """
    if not input_text:
        return ""
    text = BeautifulSoup(input_text, "lxml").get_text(separator="\n")
    return re.sub('\n\n', '\n', text)


SUMMARY_MAX_CHARS = 220
_URL_RE = re.compile(r"https?://\S+")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9])")


def one_liner(text, limit=SUMMARY_MAX_CHARS):
    """
    Short one-line summary of a feed description: drops the 'Description' header,
    'Read more at <url>' boilerplate and bare URLs, then keeps the first sentence
    (cut at a word boundary if it is still too long).
    """
    text = clean_html(text or "")
    text = re.sub(r"(?is)read more at.*$", "", text)
    text = _URL_RE.sub("", text)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if lines and lines[0].lower().rstrip(":") in ("description", "summary", "overview"):
        lines = lines[1:]
    flat = " ".join(lines)
    if not flat:
        return ""
    first = _SENTENCE_END.split(flat, maxsplit=1)[0].strip()
    if len(first) > limit:
        first = first[:limit].rsplit(" ", 1)[0].rstrip(",;:- ") + "..."
    return first


def _cve_headline(cve_ids, title, severity, kev, alarm):
    """'HIGH: CVE-2026-1234' (up to 3 ids), with the title appended when it adds information."""
    shown = ", ".join(cve_ids[:3]) + (f" +{len(cve_ids) - 3} more" if len(cve_ids) > 3 else "")
    ids = r"CVE-\d{4}-\d{4,}"
    clean = re.sub(rf"\(\s*{ids}(?:\s*[,/&]\s*{ids})*\s*\)", "", title or "", flags=re.IGNORECASE)
    clean = re.sub(ids, "", clean, flags=re.IGNORECASE)
    clean = re.sub(r"\s{2,}", " ", clean).strip(" \t:,;|-")
    text = f"{shown}: {clean}" if re.search(r"\w", clean) else shown
    if alarm:
        if severity in ("CRITICAL", "HIGH"):
            label = severity
        else:
            label = f"KEV, {severity}" if severity else "KEV"
        return f":rotating_light: *{label}*: {text}"
    return f"*{severity}*: {text}" if severity else text


def _intel_line(intel):
    """One-line summary of severity, exploitation status and EPSS."""
    parts = []
    if intel.get("severity"):
        sev = intel["severity"]
        parts.append(f"{sev} (CVSS {intel['cvss']})" if intel.get("cvss") is not None else sev)
    if intel.get("kev"):
        parts.append("exploited in the wild (CISA KEV)")
    if intel.get("epss") is not None:
        parts.append(f"EPSS {intel['epss'] * 100:.1f}%")
    return " | ".join(parts)


def build_results_message(feed_results, rss_found_already, rss_type):
    """
    Build the list of messages to post.

    :param feed_results: Full list of processed rss posts
    :param rss_found_already: Filter for RSS articles found in Slack channel
    :param rss_type: Limited to News or CVE type articles
    :return: list of {"headline", "body", "alarm"}
    """
    items = []

    for rss_post in feed_results.get("articles") or []:
        # Skip if we've already posted this based on MD5 or link
        if rss_post['md5'] in rss_found_already['md5s']:
            continue
        elif rss_post['link'] in rss_found_already['links']:
            continue

        post_title = rss_post.get("title", "No Title")
        post_summary = rss_post.get("summary", "")
        post_title_lower = post_title.lower()
        post_summary_lower = post_summary.lower()

        footer = (
            f" • link: {rss_post['link']}\n"
            f" • md5: {rss_post['md5']}\n"
            f" • keyword(s): {rss_post.get('keywords', [])}\n"
            f" • feed: {rss_post.get('rss_feed_name', 'N/A')}\n"
        )

        # Publishing News
        if rss_type == "news":
            if "cve" not in post_title_lower and "vulnerability" not in post_title_lower:
                items.append({"headline": f"\n{post_title}", "body": footer, "alarm": False})

        # Publishing CVEs
        elif rss_type == "cve":
            if "cve" in post_title_lower or "cve" in post_summary_lower:
                cve_regex = r"(CVE-20[0-9]{2}-\d+)"

                # Find all unique CVEs in title and summary
                found_cves = set(re.findall(cve_regex, f"{post_title} {post_summary}", re.IGNORECASE))

                # Skip the article when every CVE in it has already been seen
                if found_cves and found_cves.issubset(set(rss_found_already['seen_cves'])):
                    continue

                intel = rss_post.get("intel") or {}
                per_cve = intel.get("cves", {})
                cve_url_list = []
                for cve_id in sorted(found_cves):
                    addon = ""
                    if cve_id in rss_found_already["fixed_cves"]:
                        addon += ":white_check_mark:"
                    elif cve_id in rss_found_already["seen_cves"]:
                        addon += ":eyes:"
                    score = (per_cve.get(cve_id) or {}).get("cvss")
                    score_txt = f" ({score})" if score is not None else ""
                    cve_url_list.append(
                        f"<https://nvd.nist.gov/vuln/detail/{cve_id}|{cve_id}{score_txt} {addon}>")

                summary_line = one_liner(post_summary) or one_liner(post_title)
                intel_line = _intel_line(intel) or "unknown (not yet rated)"
                body = ""
                if summary_line:
                    body += f" • summary: {summary_line}\n"
                body += f" • severity: {intel_line}\n"
                if cve_url_list:
                    body += f" • cve(s): {', '.join(cve_url_list)}\n"
                body += footer

                alarm = bool(rss_post.get("alarm"))
                headline = _cve_headline(sorted(found_cves), post_title, intel.get("severity"),
                                         intel.get("kev"), alarm)
                items.append({"headline": headline, "body": body, "alarm": alarm})

    return items


def send_message(job_type, message_params, matched, errors, check_stale_keywords=None):
    """
    Send prepared RSS feed results to Slack

    :param job_type: CVE or NEWs job type
    :param message_params: Dictionary of message config values
    :param matched: Keyword matched RSS articles
    :param errors: List of feeds that have an error
    :param check_stale_keywords: None or date
    :return: True if all article posts succeeded (or there were none), False on
             failure, None if Slack is disabled or unconfigured (nothing was posted)
    """
    if str(message_params.get("slack_enabled")).lower() != "true":
        logger.info("Slack is not enabled in the configuration.")
        return None

    slack_token = message_params.get("slack_token")
    if not slack_token:
        logger.warning(f"Warning: No Slack token set. No {job_type} items will be posted to Slack.")
        return None

    try:
        slack_client = init_slack_client(slack_token)
        channel_id = message_params.get("channels", {}).get(job_type)
        error_channel_id = message_params.get("channels", {}).get("error")

        if not channel_id:
            logger.error(f"No Slack channel ID found for job type '{job_type}' in configuration.")
            return False

        # --- Post matched articles ---
        rss_found = read_channel(slack_client, channel_id, job_type)
        message_items = build_results_message(matched, rss_found, job_type)
        logger.info(f"For job '{job_type}', {len(message_items)} message(s) to post "
                    f"({sum(1 for m in message_items if m['alarm'])} alarm)")
        posted_ok = True
        if message_items:
            posted_ok = post_message(slack_client, channel_id, message_items)

        # --- Post errors and warnings to the error channel ---
        if not error_channel_id:
            logger.warning("No error channel configured for posting feed errors or stale keyword warnings.")
            return posted_ok
            
        error_message_body = ""
        if errors:
            error_message_body += "The following feeds encountered errors or are offline:\n"
            error_message_body += "\n".join([f"• {feed}" for feed in errors])
            error_message_body += "\n"

        if check_stale_keywords:
            error_message_body += f"\nKeyword list was last updated on: {str(check_stale_keywords)}\n"
            error_message_body += "It is over 90 days old and should be reviewed.\n"

        if error_message_body:
            # Post a single summary message for all errors
            post_message(slack_client, error_channel_id, error_message_body)

        return posted_ok

    except Exception as e:
        logger.error(f"An unexpected error occurred in send_message: {e}")
        return False