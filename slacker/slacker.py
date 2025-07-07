import logging
import re
from bs4 import BeautifulSoup
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import json
import time 


# Set module logger name
logger = logging.getLogger(__name__)


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
        # TODO handle paginating multiple pages
        result = client.conversations_history(channel=channel_id)
        conversation_history = result["messages"]

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


def post_message(client, channel_id, messages):
    """
    This requires the following scopes:
      chat:write:bot
        Send messages as @syphon

    :param client: Slack Client Object
    :param channel_id: Slack Channel ID
    :param messages: Message body content
    """
    for message in messages.split('\n---EOM---'):
        if message:
            try:
                # Call the chat.postMessage method using the WebClient
                result = client.chat_postMessage(
                    channel=channel_id,
                    text=message,
                    unfurl_links=False,
                    unfurl_media=False,
                    parse="mrkdwn"
                )
                logger.info(result)
                time.sleep(1) 
            except SlackApiError as e:
                msg = f"Error posting message: {e}"
                logger.error(msg)


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


def build_results_message(feed_results, rss_found_already, rss_type):
    """
    Build message which will be used as the content body

    :param feed_results: Full list of processed rss posts
    :param rss_found_already: Filter for RSS articles found in Slack channel
    :param rss_type: Limited to News or CVE type articles
    :return: Message body content
    """
    res = ""

    if feed_results.get("articles"):
        for rss_post in feed_results["articles"]:
            # Skip if we've already posted this based on MD5 or link
            if rss_post['md5'] in rss_found_already['md5s']:
                continue
            elif rss_post['link'] in rss_found_already['links']:
                continue
            
            post_title = rss_post.get("title", "No Title")
            post_summary = rss_post.get("summary", "")
            post_title_lower = post_title.lower()
            post_summary_lower = post_summary.lower()

            # Publishing News
            if rss_type == "news":
                if "cve" not in post_title_lower and "vulnerability" not in post_title_lower:
                    res += f"\n{post_title}\n"
                    res += f" • link: {rss_post['link']}\n"
                    res += f" • md5: {rss_post['md5']}\n"
                    res += f" • keyword(s): {rss_post.get('keywords', [])}\n"
                    res += f" • feed: {rss_post.get('rss_feed_name', 'N/A')}\n"
                    res += f"---EOM---"

            # Publishing CVEs
            elif rss_type == "cve":
                if "cve" in post_title_lower or "cve" in post_summary_lower:
                    cve_list = []
                    cve_url_list = []
                    cve_regex = r"(CVE-20[0-9]{2}-\d+)"

                    # Find all unique CVEs in title and summary
                    found_cves = set(re.findall(cve_regex, f"{post_title} {post_summary}", re.IGNORECASE))

                    for cve_id in sorted(list(found_cves)):
                        addon = ""
                        if cve_id in rss_found_already["fixed_cves"]:
                            addon += ":already_fixed:"
                        elif cve_id in rss_found_already["seen_cves"]:
                            addon += ":already_seen:"
                        cve_url_list.append(
                            f"<https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}|{cve_id} {addon}>")

                    cve_links = ", ".join(cve_url_list)

                    res += f"\n{post_title}\n"
                    if post_summary:
                        res += f" • summary: {clean_html(post_summary)}\n"
                    if cve_links:
                        res += f"\n • cve(s): {cve_links}\n"
                    res += f" • link: {rss_post['link']}\n"
                    res += f" • md5: {rss_post['md5']}\n"
                    res += f" • keyword(s): {rss_post.get('keywords', [])}\n"
                    res += f" • feed: {rss_post.get('rss_feed_name', 'N/A')}\n"
                    res += f"---EOM---"

    return res


def send_message(job_type, message_params, matched, errors, check_stale_keywords=None):
    """
    Send prepared RSS feed results to Slack

    :param job_type: CVE or NEWs job type
    :param message_params: Dictionary of message config values
    :param matched: Keyword matched RSS articles
    :param errors: List of feeds that have an error
    :param check_stale_keywords: None or date
    """
    if str(message_params.get("slack_enabled")).lower() != "true":
        logger.info("Slack is not enabled in the configuration.")
        return

    slack_token = message_params.get("slack_token")
    if not slack_token:
        logger.warning(f"Warning: No Slack token set. No {job_type} items will be posted to Slack.")
        return

    try:
        slack_client = init_slack_client(slack_token)
        channel_id = message_params.get("channels", {}).get(job_type)
        error_channel_id = message_params.get("channels", {}).get("error")

        if not channel_id:
            logger.error(f"No Slack channel ID found for job type '{job_type}' in configuration.")
            return

        # --- Post matched articles ---
        rss_found = read_channel(slack_client, channel_id, job_type)
        message_body = build_results_message(matched, rss_found, job_type)
        logger.info(f"For job '{job_type}', built message body: '{message_body[:200]}...'")
        if message_body:
            post_message(slack_client, channel_id, message_body)

        # --- Post errors and warnings to the error channel ---
        if not error_channel_id:
            logger.warning("No error channel configured for posting feed errors or stale keyword warnings.")
            return
            
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

    except Exception as e:
        logger.error(f"An unexpected error occurred in send_message: {e}")