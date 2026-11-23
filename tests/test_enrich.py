from rss_syphon import enrich
from rss_syphon.state import MemoryState
from slacker import slacker


def nvd(score, sev, key="cvssMetricV31"):
    return {"vulnerabilities": [{"cve": {"metrics": {key: [{"cvssData": {"baseScore": score, "baseSeverity": sev}}]}}}]}


def fake_get(table):
    def get(url, timeout=20, headers=None):
        for needle, payload in table.items():
            if needle in url:
                if isinstance(payload, Exception):
                    raise payload
                return payload
        raise AssertionError(url)
    return get


def articles(*texts):
    return [{"title": t, "summary": "", "link": f"https://x/{i}", "md5": f"{i:032d}", "keywords": ["k"],
             "rss_feed_name": "f"} for i, t in enumerate(texts)]


def test_extract_cves_dedup_and_case():
    assert enrich.extract_cves("cve-2025-0001 and CVE-2025-0001", "CVE-2024-12345") == ["CVE-2024-12345", "CVE-2025-0001"]


def test_best_cvss_prefers_newest_version():
    assert enrich.best_cvss(nvd(9.8, "CRITICAL")) == (9.8, "CRITICAL")
    assert enrich.best_cvss({"vulnerabilities": []}) == (None, None)


def test_critical_sets_alarm_and_caches():
    state = MemoryState()
    get = fake_get({"known_exploited": {"vulnerabilities": []}, "epss": {"data": [{"cve": "CVE-2025-0001", "epss": "0.5"}]},
                    "cveId=CVE-2025-0001": nvd(9.8, "CRITICAL")})
    arts = enrich.enrich_articles(articles("CVE-2025-0001 in thing"), state, get=get, sleep=lambda s: None)
    assert arts[0]["alarm"] is True
    assert arts[0]["intel"]["severity"] == "CRITICAL" and arts[0]["intel"]["epss"] == 0.5
    assert state.get_cve("CVE-2025-0001")["severity"] == "CRITICAL"


def test_medium_without_kev_is_not_alarm():
    get = fake_get({"known_exploited": {"vulnerabilities": []}, "epss": {"data": []}, "cveId=": nvd(5.0, "MEDIUM")})
    arts = enrich.enrich_articles(articles("CVE-2025-0002 meh"), MemoryState(), get=get, sleep=lambda s: None)
    assert arts[0]["alarm"] is False


def test_kev_alone_triggers_alarm():
    get = fake_get({"known_exploited": {"vulnerabilities": [{"cveID": "CVE-2025-0003"}]}, "epss": {"data": []},
                    "cveId=": nvd(5.0, "MEDIUM")})
    arts = enrich.enrich_articles(articles("CVE-2025-0003 exploited"), MemoryState(), get=get, sleep=lambda s: None)
    assert arts[0]["alarm"] is True and arts[0]["intel"]["kev"] is True


def test_sources_failing_still_returns_articles():
    boom = RuntimeError("down")
    get = fake_get({"known_exploited": boom, "epss": boom, "cveId=": boom})
    arts = enrich.enrich_articles(articles("CVE-2025-0004 x"), MemoryState(), get=get, sleep=lambda s: None)
    assert arts[0]["alarm"] is False and arts[0]["intel"]["severity"] is None


def test_cache_avoids_nvd_lookup():
    state = MemoryState()
    state.set_cve("CVE-2025-0005", 8.0, "HIGH")
    get = fake_get({"known_exploited": {"vulnerabilities": []}, "epss": {"data": []}})  # NVD would assert
    arts = enrich.enrich_articles(articles("CVE-2025-0005 y"), state, get=get, sleep=lambda s: None)
    assert arts[0]["alarm"] is True


def test_nvd_budget_limits_lookups(monkeypatch):
    monkeypatch.setenv("NVD_MAX_LOOKUPS", "1")
    calls = []
    def get(url, timeout=20, headers=None):
        if "known_exploited" in url: return {"vulnerabilities": []}
        if "epss" in url: return {"data": []}
        calls.append(url); return nvd(8.0, "HIGH")
    enrich.enrich_articles(articles("CVE-2025-0006 a", "CVE-2025-0007 b"), MemoryState(), get=get, sleep=lambda s: None)
    assert len(calls) == 1


def test_slack_alarm_is_red_with_rotating_light():
    arts = articles("CVE-2025-0008 big bug")
    arts[0]["alarm"] = True
    arts[0]["intel"] = {"cves": {"CVE-2025-0008": {"cvss": 9.8}}, "severity": "CRITICAL", "cvss": 9.8, "kev": True, "epss": 0.9}
    found = {"md5s": [], "links": [], "seen_cves": [], "fixed_cves": []}
    items = slacker.build_results_message({"articles": arts}, found, "cve")
    assert len(items) == 1 and items[0]["alarm"] is True
    assert items[0]["headline"].startswith(":rotating_light: *CRITICAL*")
    kw = slacker._post_kwargs(items[0])
    assert kw["attachments"][0]["color"] == "#D50000"
    assert "CISA KEV" in kw["attachments"][0]["text"] and "(9.8)" in kw["attachments"][0]["text"]


def test_slack_non_alarm_has_no_attachment():
    arts = articles("CVE-2025-0009 small bug")
    found = {"md5s": [], "links": [], "seen_cves": [], "fixed_cves": []}
    items = slacker.build_results_message({"articles": arts}, found, "cve")
    assert "attachments" not in slacker._post_kwargs(items[0])


def test_budget_exhausted_defers_article(monkeypatch):
    monkeypatch.setenv("NVD_MAX_LOOKUPS", "1")
    def get(url, timeout=20, headers=None):
        if "known_exploited" in url: return {"vulnerabilities": []}
        if "epss" in url: return {"data": []}
        return nvd(8.0, "HIGH")
    arts = enrich.enrich_articles(articles("CVE-2025-0010 a", "CVE-2025-0011 b"), MemoryState(), get=get, sleep=lambda s: None)
    assert [a["deferred"] for a in arts] == [False, True]


def test_lookup_failure_does_not_defer():
    boom = RuntimeError("down")
    get = fake_get({"known_exploited": {"vulnerabilities": []}, "epss": {"data": []}, "cveId=": boom})
    arts = enrich.enrich_articles(articles("CVE-2025-0012 a"), MemoryState(), get=get, sleep=lambda s: None)
    assert arts[0]["deferred"] is False
