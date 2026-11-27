import time
import unittest
from unittest import mock

from remediator.web import app as web_app
from remediator.web import security
from remediator.web.store import ScanStore

TOKEN = "t" * 32
VALID_ID = "scan_" + "a" * 16


class ValidateStartupTest(unittest.TestCase):
    def test_loopback_without_token_is_allowed(self):
        for host in ("127.0.0.1", "localhost", "::1"):
            security.validate_startup(host, "")

    def test_all_interfaces_are_refused(self):
        for host in ("0.0.0.0", "::", ""):
            with self.subTest(host=host), self.assertRaises(RuntimeError):
                security.validate_startup(host, TOKEN)

    def test_non_loopback_needs_token(self):
        with self.assertRaises(RuntimeError):
            security.validate_startup("10.1.2.3", "")
        security.validate_startup("10.1.2.3", TOKEN)

    def test_short_token_is_refused(self):
        with self.assertRaises(RuntimeError):
            security.validate_startup("127.0.0.1", "short")


class HelpersTest(unittest.TestCase):
    def test_token_matches(self):
        self.assertTrue(security.token_matches(TOKEN, TOKEN))
        self.assertFalse(security.token_matches("x" * 32, TOKEN))
        self.assertFalse(security.token_matches("", TOKEN))
        self.assertFalse(security.token_matches(TOKEN, ""))

    def test_request_token(self):
        self.assertEqual(security.request_token({"Authorization": f"Bearer {TOKEN}"}), TOKEN)
        for value in ("", "Basic abc", "Bearer", "Bearer a b", f"bearer {TOKEN}"):
            with self.subTest(value=value):
                self.assertEqual(security.request_token({"Authorization": value}), "")

    def test_host_is_allowed(self):
        with mock.patch.dict("os.environ", {"ALLOWED_HOSTS": "audesec.example.com"}):
            for host in ("localhost:8000", "127.0.0.1", "[::1]:8000", "AudeSec.Example.com",
                         "10.0.0.5:8000"):
                with self.subTest(host=host):
                    self.assertTrue(security.host_is_allowed(host, "10.0.0.5"))
            for host in ("evil.com", "evil.com:8000", "", None, "localhost.evil.com"):
                with self.subTest(host=host):
                    self.assertFalse(security.host_is_allowed(host, "10.0.0.5"))

    def test_scan_ids(self):
        scan_id = security.new_scan_id()
        self.assertRegex(scan_id, security.SCAN_ID_PATTERN)
        self.assertNotEqual(scan_id, security.new_scan_id())
        for bad in ("scan_1", "../etc/passwd", VALID_ID + "\n", "scan_" + "a" * 17):
            with self.subTest(bad=bad):
                self.assertIsNone(security.SCAN_ID_PATTERN.match(bad))


class ScanStoreTest(unittest.TestCase):
    def test_concurrency_cap(self):
        store = ScanStore(max_concurrent=1)
        self.assertTrue(store.try_start("a"))
        self.assertFalse(store.try_start("b"))
        store.set("a", status="complete")
        self.assertTrue(store.try_start("b"))

    def test_snapshot_is_a_copy(self):
        store = ScanStore()
        store.try_start("a")
        store.append_step("a", {"step": 1})
        snap = store.snapshot("a")
        snap["steps"].append({"step": 2})
        self.assertEqual(len(store.get("a", "steps")), 1)
        self.assertIsNone(store.snapshot("missing"))
        with self.assertRaises(KeyError):
            store["missing"]

    def test_retention_evicts_finished_scans(self):
        store = ScanStore(retention_seconds=10)
        store.try_start("old")
        store.set("old", status="complete")
        store._finished_at["old"] = time.time() - 100
        store.try_start("new")
        self.assertNotIn("old", store)
        self.assertIn("new", store)

    def test_max_stored_drops_oldest_finished(self):
        store = ScanStore(max_concurrent=10, max_stored=2)
        for name in ("a", "b"):
            store.try_start(name)
            store.set(name, status="complete")
        store._finished_at["a"] -= 5
        store.try_start("c")
        self.assertNotIn("a", store)
        self.assertIn("b", store)


class WebAppTest(unittest.TestCase):
    def setUp(self):
        web_app.app.config["TESTING"] = False  # keep the real error handlers
        self.client = web_app.app.test_client()
        web_app.scan_results.clear()
        patcher = mock.patch.dict("os.environ", {"AUDESEC_ACCESS_TOKEN": TOKEN})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(web_app.scan_results.clear)
        self.auth = {"Authorization": f"Bearer {TOKEN}"}

    def test_healthz_needs_no_token(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "ok"})

    def test_security_headers(self):
        response = self.client.get("/healthz")
        self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_index_has_no_inline_script(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"onclick=", response.data)
        self.assertNotIn(b"<script>", response.data)

    def test_bad_host_is_forbidden(self):
        response = self.client.get("/healthz", headers={"Host": "evil.com"})
        self.assertEqual(response.status_code, 403)

    def test_foreign_origin_is_forbidden(self):
        response = self.client.post("/api/scan", headers={**self.auth, "Origin": "https://evil.com"},
                                    json={"repo_url": "https://github.com/a/b.git"})
        self.assertEqual(response.status_code, 403)

    def test_api_requires_token(self):
        self.assertEqual(self.client.post("/api/scan", json={}).status_code, 401)
        self.assertEqual(
            self.client.get(f"/api/scan/{VALID_ID}", headers={"Authorization": "Bearer wrong"}).status_code,
            401)

    def test_api_open_when_no_token_configured(self):
        with mock.patch.dict("os.environ", {"AUDESEC_ACCESS_TOKEN": ""}):
            self.assertEqual(self.client.post("/api/scan", json={}).status_code, 400)

    def test_missing_or_invalid_repo_url(self):
        for payload in ({}, {"repo_url": ""}, {"repo_url": "file:///etc"}, {"repo_url": "http://x/y"}):
            with self.subTest(payload=payload):
                response = self.client.post("/api/scan", headers=self.auth, json=payload)
                self.assertEqual(response.status_code, 400)
        response = self.client.post("/api/scan", headers=self.auth, data="not json")
        self.assertEqual(response.status_code, 400)

    def test_unknown_and_malformed_scan_ids_return_404(self):
        for scan_id in (VALID_ID, "scan_1", "x"):
            with self.subTest(scan_id=scan_id):
                response = self.client.get(f"/api/scan/{scan_id}", headers=self.auth)
                self.assertEqual(response.status_code, 404)

    def test_start_scan_and_read_status(self):
        with mock.patch.object(web_app, "run_security_scan") as run:
            response = self.client.post("/api/scan", headers=self.auth,
                                        json={"repo_url": "https://github.com/a/b.git"})
        self.assertEqual(response.status_code, 200)
        scan_id = response.get_json()["scan_id"]
        self.assertRegex(scan_id, security.SCAN_ID_PATTERN)
        run.assert_called_once()
        status = self.client.get(f"/api/scan/{scan_id}", headers=self.auth)
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.get_json()["status"], "running")

    def test_too_many_scans_returns_429(self):
        with mock.patch.object(web_app, "run_security_scan"), \
                mock.patch.object(web_app.scan_results, "max_concurrent", 1):
            payload = {"repo_url": "https://github.com/a/b.git"}
            self.assertEqual(self.client.post("/api/scan", headers=self.auth, json=payload).status_code, 200)
            self.assertEqual(self.client.post("/api/scan", headers=self.auth, json=payload).status_code, 429)

    def test_large_body_returns_413(self):
        response = self.client.post("/api/scan", headers=self.auth,
                                    data=b"x" * (web_app.app.config["MAX_CONTENT_LENGTH"] + 1),
                                    content_type="application/json")
        self.assertEqual(response.status_code, 413)

    def test_unexpected_error_is_generic(self):
        with mock.patch.object(web_app.scan_results, "snapshot", side_effect=RuntimeError("secret detail")):
            response = self.client.get(f"/api/scan/{VALID_ID}", headers=self.auth)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json(), {"error": "Internal server error"})
        self.assertNotIn(b"secret detail", response.data)

    def test_unknown_route_and_method(self):
        self.assertEqual(self.client.get("/nope").status_code, 404)
        self.assertEqual(self.client.get("/api/scan", headers=self.auth).status_code, 405)


if __name__ == "__main__":
    unittest.main()
