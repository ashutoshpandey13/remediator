"""
Thread-safe in-memory store for scan state.

Scans run in background threads while HTTP threads read them, so every access goes
through one lock and readers get copies. Finished scans are dropped after a retention
period, and the number of scans running at once is capped.
"""
import copy
import threading
import time

DEFAULT_MAX_CONCURRENT_SCANS = 2
DEFAULT_RETENTION_SECONDS = 24 * 3600
DEFAULT_MAX_STORED_SCANS = 200


class ScanStore:
    def __init__(self, max_concurrent=DEFAULT_MAX_CONCURRENT_SCANS,
                 retention_seconds=DEFAULT_RETENTION_SECONDS,
                 max_stored=DEFAULT_MAX_STORED_SCANS):
        self._lock = threading.RLock()
        self._scans = {}
        self._finished_at = {}
        self.max_concurrent = max_concurrent
        self.retention_seconds = retention_seconds
        self.max_stored = max_stored

    # ---- writes -------------------------------------------------------------
    def try_start(self, scan_id):
        """Register a new running scan. Returns False when too many scans are running."""
        with self._lock:
            self._evict()
            running = sum(1 for scan in self._scans.values() if scan.get("status") == "running")
            if running >= self.max_concurrent:
                return False
            self._scans[scan_id] = {"steps": [], "status": "running"}
            return True

    def ensure(self, scan_id):
        """Create the scan entry if it does not exist yet (running scans only)."""
        with self._lock:
            self._scans.setdefault(scan_id, {"steps": [], "status": "running"})

    def append_step(self, scan_id, progress):
        with self._lock:
            self._scans.setdefault(scan_id, {"steps": [], "status": "running"})["steps"].append(progress)

    def set(self, scan_id, **values):
        with self._lock:
            scan = self._scans.setdefault(scan_id, {"steps": [], "status": "running"})
            scan.update(values)
            if values.get("status") in ("complete", "error"):
                self._finished_at[scan_id] = time.time()

    # ---- reads --------------------------------------------------------------
    def get(self, scan_id, key, default=None):
        with self._lock:
            return self._scans.get(scan_id, {}).get(key, default)

    def snapshot(self, scan_id):
        """A deep copy of one scan (None if unknown), safe to serialise while the scan runs."""
        with self._lock:
            scan = self._scans.get(scan_id)
            return copy.deepcopy(scan) if scan is not None else None

    def __contains__(self, scan_id):
        with self._lock:
            return scan_id in self._scans

    def __getitem__(self, scan_id):
        snapshot = self.snapshot(scan_id)
        if snapshot is None:
            raise KeyError(scan_id)
        return snapshot

    def clear(self):
        with self._lock:
            self._scans.clear()
            self._finished_at.clear()

    # ---- retention ----------------------------------------------------------
    def _evict(self):
        """Drop finished scans that are past retention, then the oldest finished ones over the cap."""
        now = time.time()
        for scan_id, finished in list(self._finished_at.items()):
            if now - finished > self.retention_seconds:
                self._scans.pop(scan_id, None)
                self._finished_at.pop(scan_id, None)

        if len(self._scans) >= self.max_stored:
            for scan_id, _ in sorted(self._finished_at.items(), key=lambda item: item[1]):
                if len(self._scans) < self.max_stored:
                    break
                self._scans.pop(scan_id, None)
                self._finished_at.pop(scan_id, None)
