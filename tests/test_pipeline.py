import os
import time
from datetime import datetime, timedelta, timezone
from calendar import timegm

os.environ.setdefault("SYPHON_CONFIG_MODULE", "rss_data")

from rss_syphon import rss_feed as rf
from rss_syphon.state import FileState, MemoryState
from slacker import slacker

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)


def entry(title, hours_ago, link=None, summary=""):
    ts = (NOW - timedelta(hours=hours_ago)).timetuple()
    return {"title": title, "summary": summary, "link": link or f"https://x/{title}",
            "published_parsed": time.gmtime(timegm(ts))}


def run(entries, kws, ignore=(), seen=None, hours=36):
    feeds = [({"entries": entries}, "feed")]
    return rf.prepare_feed_message(feeds, rf.compile_keywords(kws), rf.compile_ignored(ignore),
                                   hours, seen=seen, now=NOW)[0]["articles"]


def test_keyword_word_boundaries_and_case():
    arts = run([entry("Okta breach", 1), entry("Bokta thing", 1)], ["okta"])
    assert [a["title"] for a in arts] == ["Okta breach"]


def test_keywords_are_escaped():
    assert run([entry("c++ flaw", 1)], ["c++"])
    assert not run([entry("cxx flaw", 1)], ["c(+"])  # would raise if unescaped


def test_ignore_list_is_applied():
    assert not run([entry("We are hiring: okta", 1)], ["okta"], ignore=["hiring"])


def test_lookback_window():
    arts = run([entry("okta new", 10), entry("okta old", 40)], ["okta"], hours=36)
    assert [a["title"] for a in arts] == ["okta new"]


def test_seen_and_duplicates_skipped():
    e = entry("okta a", 1)
    first = run([e, dict(e)], ["okta"])
    assert len(first) == 1
    assert run([e], ["okta"], seen=lambda u: u == first[0]["uid"]) == []


def test_same_title_different_link_is_distinct():
    arts = run([entry("okta a", 1, link="https://x/1"), entry("okta a", 1, link="https://x/2")], ["okta"])
    assert len(arts) == 2


def test_adjacent_keywords_not_glued():
    import rss_data, rss_data_vsa
    for kws in (rss_data.keywords["static_keywords"], rss_data_vsa.keywords["static_keywords"]):
        assert "abnormalai" not in kws and "N8Nslack" not in kws


def test_file_state_roundtrip_and_prune(tmp_path):
    p = str(tmp_path / "s.json")
    s = FileState(p)
    s.mark_seen(["a"], now=time.time())
    s.mark_seen(["old"], now=time.time() - 90 * 86400)
    s.set_validators("u", etag="e1")
    s.save()
    s2 = FileState(p)
    s2.load()
    assert s2.is_seen("a") and not s2.is_seen("old")
    assert s2.get_validators("u")["etag"] == "e1"


def test_deployments_do_not_share_file_state(tmp_path, monkeypatch):
    monkeypatch.setenv("STATE_BACKEND", "file")
    monkeypatch.chdir(tmp_path)
    from rss_syphon.state import get_state
    a, b = get_state("team", "cve"), get_state("privacy", "cve")
    a.mark_seen(["x"]); a.save()
    b2 = get_state("privacy", "cve")
    assert not b2.is_seen("x") and get_state("team", "cve").is_seen("x")


class FakeClient:
    def __init__(self, fail=False): self.fail, self.sent = fail, []
    def chat_postMessage(self, **kw):
        if self.fail:
            raise slacker.SlackApiError("boom", {"error": "x"})
        self.sent.append(kw["text"]); return {}


def test_post_message_reports_failure(monkeypatch):
    monkeypatch.setattr(slacker.time, "sleep", lambda s: None)
    assert slacker.post_message(FakeClient(), "C", "a\n---EOM---b---EOM---") is True
    assert slacker.post_message(FakeClient(fail=True), "C", "a---EOM---") is False


def test_send_message_tristate(monkeypatch):
    assert slacker.send_message("cve", {"slack_enabled": "false"}, {}, []) is None
    params = {"slack_enabled": "true", "slack_token": "t", "channels": {}}
    assert slacker.send_message("cve", params, {}, []) is False


def test_bad_timestamp_does_not_raise():
    bad = {"title": "okta", "link": "https://x/bad", "published_parsed": time.struct_time((0, 1, 1, 0, 0, 0, 0, 1, 0))}
    feeds = [({"entries": [bad]}, "feed")]
    matched, errors, date_errors, _ = rf.prepare_feed_message(
        feeds, rf.compile_keywords(["okta"]), None, 36, now=NOW)
    assert matched["articles"] == [] and errors == [] and date_errors == ["feed"]


def test_keyword_lists_have_no_duplicates_or_glued_words():
    import rss_data, rss_data_vsa
    for m in (rss_data, rss_data_vsa):
        k = m.keywords["static_keywords"]
        assert len(k) == len(set(k)), m.__name__
        assert all(w == w.strip() and w for w in k)
    team = rss_data.keywords["static_keywords"]
    for noisy in ("ai", "agi", "h1"):
        assert noisy not in team


def test_seed_only_marks_seen_without_posting(monkeypatch, tmp_path):
    monkeypatch.setenv("SEED_ONLY", "true")
    monkeypatch.setenv("STATE_BACKEND", "file")
    monkeypatch.chdir(tmp_path)
    posted = []
    monkeypatch.setattr(rf, "send_message", lambda **kw: posted.append(kw))
    monkeypatch.setattr(rf, "fetch_feed_results", lambda feeds, state=None, nv=None: [({"entries": [entry("okta flaw", 1)]}, "feed")])
    monkeypatch.setattr(rf, "rss_feed_list", {"news": [{"name": "feed", "url": "https://x"}]})
    monkeypatch.setattr(rf, "keywords_data", {"static_keywords": ["okta"], "ignored": [], "last_modified": None})
    monkeypatch.setattr(rf, "datetime", type("D", (), {"now": staticmethod(lambda tz=None: NOW),
                                                      "strptime": staticmethod(datetime.strptime),
                                                      "fromtimestamp": staticmethod(datetime.fromtimestamp)}))
    assert rf.run_job("news") is True
    assert posted == []
    from rss_syphon.state import get_state
    assert len(get_state(rf.DEPLOYMENT, "news").seen) == 1
