"""
Persistent state for RSS-Syphon, shared by every run of one deployment.

State is namespaced by SYPHON_DEPLOYMENT so several deployments (for example
the security team job and the privacy team job) never see each other's data.

Backends:
  firestore (default when STATE_BACKEND is unset and google-cloud-firestore
             is installed): one document per deployment and job type.
  file      JSON file, for local runs and tests (STATE_FILE overrides path).
  memory    nothing persisted.

Document shape:
  {"seen": {uid: unix_ts}, "validators": {feed_url: {"etag":..,"last_modified":..}},
   "cve_cache": {cve_id: {"cvss":.., "severity":.., "ts":..}}}
"""
import json
import logging
import os
import time

logger = logging.getLogger(__name__)

SEEN_TTL_DAYS = int(os.getenv("SEEN_TTL_DAYS", "30"))


class State:
    """In-memory state with load/save hooks implemented by subclasses."""

    def __init__(self):
        self.seen = {}
        self.validators = {}
        self.cve_cache = {}  # cve_id -> {"cvss": float|None, "severity": str|None, "ts": unix}

    # -- subclass hooks ---------------------------------------------------
    def load(self):
        pass

    def save(self):
        pass

    # -- API used by the pipeline ------------------------------------------
    def is_seen(self, uid):
        return uid in self.seen

    def mark_seen(self, uids, now=None):
        now = now or time.time()
        for uid in uids:
            self.seen[uid] = now

    def prune(self, now=None):
        cutoff = (now or time.time()) - SEEN_TTL_DAYS * 86400
        self.seen = {k: v for k, v in self.seen.items() if v >= cutoff}
        self.cve_cache = {k: v for k, v in self.cve_cache.items() if v.get("ts", 0) >= cutoff}

    def get_validators(self, url):
        return self.validators.get(url, {})

    def set_validators(self, url, etag=None, last_modified=None):
        if etag or last_modified:
            self.validators[url] = {"etag": etag, "last_modified": last_modified}

    def get_cve(self, cve_id):
        return self.cve_cache.get(cve_id)

    def set_cve(self, cve_id, cvss, severity):
        self.cve_cache[cve_id] = {"cvss": cvss, "severity": severity, "ts": time.time()}

    def _to_doc(self):
        return {"seen": self.seen, "validators": self.validators, "cve_cache": self.cve_cache}

    def _from_doc(self, doc):
        doc = doc or {}
        self.seen = {k: float(v) for k, v in (doc.get("seen") or {}).items()}
        self.validators = doc.get("validators") or {}
        self.cve_cache = doc.get("cve_cache") or {}


class MemoryState(State):
    pass


class FileState(State):
    def __init__(self, path):
        super().__init__()
        self.path = path

    def load(self):
        try:
            with open(self.path) as fh:
                self._from_doc(json.load(fh))
        except FileNotFoundError:
            pass

    def save(self):
        self.prune()
        tmp = self.path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(self._to_doc(), fh)
        os.replace(tmp, self.path)


class FirestoreState(State):
    def __init__(self, deployment, job_type, project=None):
        super().__init__()
        from google.cloud import firestore  # lazy: optional dependency
        self._client = firestore.Client(project=project)
        collection = os.getenv("STATE_COLLECTION", "rss_syphon_state")
        self._ref = self._client.collection(collection).document(f"{deployment}__{job_type}")

    def load(self):
        snap = self._ref.get()
        self._from_doc(snap.to_dict() if snap.exists else None)

    def save(self):
        self.prune()
        self._ref.set(self._to_doc())


def get_state(deployment, job_type):
    """Build and load the state store selected by STATE_BACKEND."""
    backend = os.getenv("STATE_BACKEND", "firestore").lower()
    if backend == "firestore":
        try:
            state = FirestoreState(deployment, job_type, os.getenv("GOOGLE_CLOUD_PROJECT"))
        except Exception as e:  # missing dependency or credentials
            logger.warning(f"Firestore unavailable ({e}); falling back to in-memory state")
            state = MemoryState()
    elif backend == "file":
        default = f".state_{deployment}_{job_type}.json"
        state = FileState(os.getenv("STATE_FILE", default))
    else:
        state = MemoryState()
    try:
        state.load()
    except Exception as e:
        logger.error(f"Could not load state ({e}); continuing with empty state")
        state = MemoryState()
    return state
