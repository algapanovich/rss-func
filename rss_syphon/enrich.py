"""
CVE enrichment for the CVE job.

For every CVE mentioned in a matched article we add:
  cvss / severity   NVD API 2.0 (cached in state, one lookup per CVE)
  kev               CISA Known Exploited Vulnerabilities catalog (one download per run)
  epss              FIRST EPSS exploit probability (batched)

Everything fails soft: if a source is unreachable the article is still posted,
just without that field. High/Critical severity or a KEV listing sets
article["alarm"] = True, which the Slack layer renders as a red alert.

Env:
  NVD_API_KEY          optional, raises the NVD rate limit
  NVD_MAX_LOOKUPS      max uncached NVD lookups per run (default 25)
  ENRICH_ENABLED       "false" disables enrichment
"""
import json
import logging
import os
import re
import time
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "rss-syphon/1.0"


def extract_cves(*texts):
    """Unique upper-cased CVE ids in the given texts, in sorted order."""
    found = set()
    for t in texts:
        found.update(m.upper() for m in CVE_RE.findall(t or ""))
    return sorted(found)


def severity_from_score(score):
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "NONE"


def http_get_json(url, timeout=20, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def fetch_kev(get=http_get_json):
    """Set of CVE ids in the CISA KEV catalog (empty set on failure)."""
    try:
        data = get(KEV_URL, timeout=30)
        return {v["cveID"].upper() for v in data.get("vulnerabilities", [])}
    except Exception as e:
        logger.warning(f"KEV lookup failed: {e}")
        return set()


def fetch_epss(cve_ids, get=http_get_json, chunk=50):
    """{cve_id: epss_probability} for the given ids (missing on failure)."""
    out = {}
    for i in range(0, len(cve_ids), chunk):
        part = cve_ids[i:i + chunk]
        try:
            data = get(f"{EPSS_URL}?cve={urllib.parse.quote(','.join(part))}")
            for row in data.get("data", []):
                out[row["cve"].upper()] = float(row["epss"])
        except Exception as e:
            logger.warning(f"EPSS lookup failed: {e}")
    return out


def best_cvss(nvd_json):
    """Highest-version base score in an NVD 2.0 response: (score, severity)."""
    try:
        metrics = nvd_json["vulnerabilities"][0]["cve"]["metrics"]
    except (KeyError, IndexError, TypeError):
        return None, None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            if score is not None:
                score = float(score)
                return score, (data.get("baseSeverity") or severity_from_score(score)).upper()
    return None, None


def lookup_nvd(cve_id, get=http_get_json, api_key=None):
    headers = {"apiKey": api_key} if api_key else {}
    data = get(f"{NVD_URL}?cveId={cve_id}", headers=headers)
    return best_cvss(data)


def enrich_articles(articles, state=None, get=http_get_json, sleep=time.sleep):
    """
    Attach article["intel"] and article["alarm"] to every article with CVEs.
    intel = {"cves": {id: {"cvss","severity","epss","kev"}}, "severity", "cvss", "kev", "epss"}
    """
    if os.getenv("ENRICH_ENABLED", "true").lower() == "false" or not articles:
        return articles

    for a in articles:
        a["cve_ids"] = extract_cves(a.get("title"), a.get("summary"))
    all_ids = sorted({c for a in articles for c in a["cve_ids"]})
    if not all_ids:
        return articles

    kev = fetch_kev(get)
    epss = fetch_epss(all_ids, get)

    api_key = os.getenv("NVD_API_KEY")
    budget = int(os.getenv("NVD_MAX_LOOKUPS", "25"))
    delay = 0.7 if api_key else 6.5  # NVD: 50 req/30s with key, 5 req/30s without
    cvss = {}
    for cve_id in all_ids:
        cached = state.get_cve(cve_id) if state else None
        if cached and cached.get("severity"):
            cvss[cve_id] = (cached.get("cvss"), cached.get("severity"))
            continue
        if budget <= 0:
            continue
        budget -= 1
        try:
            score, sev = lookup_nvd(cve_id, get, api_key)
            if state and sev:
                state.set_cve(cve_id, score, sev)
            cvss[cve_id] = (score, sev)
        except Exception as e:
            logger.warning(f"NVD lookup failed for {cve_id}: {e}")
        sleep(delay)

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    for a in articles:
        per_cve = {}
        for c in a["cve_ids"]:
            score, sev = cvss.get(c, (None, None))
            per_cve[c] = {"cvss": score, "severity": sev, "epss": epss.get(c), "kev": c in kev}
        sevs = [v["severity"] for v in per_cve.values() if v["severity"]]
        top = min(sevs, key=order.index) if sevs else None
        scores = [v["cvss"] for v in per_cve.values() if v["cvss"] is not None]
        epss_vals = [v["epss"] for v in per_cve.values() if v["epss"] is not None]
        a["intel"] = {
            "cves": per_cve,
            "severity": top,
            "cvss": max(scores) if scores else None,
            "kev": any(v["kev"] for v in per_cve.values()),
            "epss": max(epss_vals) if epss_vals else None,
        }
        a["alarm"] = top in ("CRITICAL", "HIGH") or a["intel"]["kev"]
    return articles
