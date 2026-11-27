import os
import types
from unittest import mock

from tests.helpers import TempDirTestCase

from remediator.web import app as web_app


def _run_recorder(stdout=""):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    return calls, fake_run


class DockerCleanupTest(TempDirTestCase):
    def test_images_are_removed_and_build_cache_pruned(self):
        calls, fake_run = _run_recorder()
        with mock.patch.dict(os.environ, {"PRUNE_BUILD_CACHE": ""}), \
                mock.patch.object(web_app.subprocess, "run", fake_run):
            web_app.remove_docker_images(["a-0", "a-0-fixed"])

        self.assertEqual(calls, [["docker", "rmi", "-f", "a-0"],
                                 ["docker", "rmi", "-f", "a-0-fixed"],
                                 ["docker", "builder", "prune", "-f"]])

    def test_cache_prune_can_be_disabled(self):
        calls, fake_run = _run_recorder()
        with mock.patch.dict(os.environ, {"PRUNE_BUILD_CACHE": "false"}), \
                mock.patch.object(web_app.subprocess, "run", fake_run):
            web_app.remove_docker_images(["a-0"])

        self.assertEqual(calls, [["docker", "rmi", "-f", "a-0"]])

    def test_nothing_built_means_nothing_pruned(self):
        calls, fake_run = _run_recorder()
        with mock.patch.object(web_app.subprocess, "run", fake_run):
            web_app.remove_docker_images([])
        self.assertEqual(calls, [])

    def test_docker_errors_do_not_break_the_scan(self):
        with mock.patch.object(web_app.subprocess, "run", side_effect=OSError("no docker")):
            web_app.remove_docker_images(["a-0"])
            web_app.remove_stale_images()

    def test_builds_are_labelled_so_leftovers_can_be_found(self):
        calls, fake_run = _run_recorder()
        with mock.patch.object(web_app.subprocess, "run", fake_run):
            web_app.build_docker_image("/repo", "svc/Dockerfile", "tag-1")

        cmd = calls[0]
        self.assertEqual(cmd[cmd.index("--label") + 1], web_app.IMAGE_LABEL)
        self.assertEqual(cmd[-1], os.path.join("/repo", "svc"))

    def test_only_old_labelled_images_are_swept(self):
        calls, fake_run = _run_recorder(stdout="id1\nid2\nid1\n")
        with mock.patch.object(web_app.subprocess, "run", fake_run):
            web_app.remove_stale_images()

        listing, removal = calls
        self.assertIn(f"label={web_app.IMAGE_LABEL}", listing)
        self.assertIn(f"until={web_app.STALE_IMAGE_MAX_AGE}", listing)
        self.assertEqual(removal, ["docker", "rmi", "-f", "id1", "id2"])

    def test_no_stale_images_means_no_removal(self):
        calls, fake_run = _run_recorder(stdout="")
        with mock.patch.object(web_app.subprocess, "run", fake_run):
            web_app.remove_stale_images()
        self.assertEqual(len(calls), 1)
