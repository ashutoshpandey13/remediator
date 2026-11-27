import os
import re

from tests.helpers import K8S_POD, TempDirTestCase, write

from remediator.config import (
    MAX_MANIFEST_BYTES,
    discover_repo_files,
    get_repository_config,
    is_k8s_manifest,
)


class DiscoverRepoFilesTest(TempDirTestCase):
    def test_nested_manifests_are_detected_by_content(self):
        write(self.tmp, "deploy/prod/app.yaml", K8S_POD)
        write(self.tmp, "k8s/svc.yml", K8S_POD)
        # name says nothing about Kubernetes; the content decides
        write(self.tmp, "misc/whatever.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
        # several documents; the manifest is not the first one
        write(self.tmp, "multi/all.yaml", "---\nfoo: bar\n---\n" + K8S_POD)

        found = discover_repo_files(self.tmp)

        self.assertEqual(found["k8s_manifests"], [
            "deploy/prod/app.yaml", "k8s/svc.yml", "misc/whatever.yaml", "multi/all.yaml",
        ])
        self.assertEqual(found["dockerfiles"], [])
        self.assertEqual(found["package_jsons"], [])

    def test_non_manifest_yaml_is_ignored(self):
        write(self.tmp, "config.yaml", "a: 1\nb: [1, 2]\n")
        write(self.tmp, ".github/workflows/ci.yml", "name: ci\non: push\njobs: {}\n")
        write(self.tmp, "only-kind.yaml", "kind: Pod\n")
        write(self.tmp, "only-api.yaml", "apiVersion: v1\n")
        write(self.tmp, "chart/templates/d.yaml", "apiVersion: v1\nkind: {{ .Values.kind }}\n")
        write(self.tmp, "empty.yaml", "")
        write(self.tmp, "list.yaml", "- apiVersion: v1\n  kind: Pod\n")
        write(self.tmp, "notes.txt", K8S_POD)

        self.assertEqual(discover_repo_files(self.tmp)["k8s_manifests"], [])

    def test_vendor_dirs_are_skipped(self):
        write(self.tmp, "node_modules/pkg/package.json", "{}")
        write(self.tmp, "node_modules/pkg/deploy.yaml", K8S_POD)
        write(self.tmp, "web/node_modules/pkg/Dockerfile", "FROM scratch\n")
        write(self.tmp, ".git/hooks/x.yaml", K8S_POD)
        write(self.tmp, "vendor/lib/Dockerfile", "FROM scratch\n")
        write(self.tmp, "vendor/lib/package.json", "{}")
        write(self.tmp, "real/deploy.yaml", K8S_POD)

        found = discover_repo_files(self.tmp)

        self.assertEqual(found["k8s_manifests"], ["real/deploy.yaml"])
        self.assertEqual(found["dockerfiles"], [])
        self.assertEqual(found["package_jsons"], [])

    def test_multiple_dockerfiles_and_package_jsons(self):
        write(self.tmp, "Dockerfile", "FROM scratch\n")
        write(self.tmp, "svc/a/Dockerfile.prod", "FROM scratch\n")
        write(self.tmp, "svc/b/app.Dockerfile", "FROM scratch\n")
        write(self.tmp, "svc/b/Dockerfile-nomatch", "FROM scratch\n")
        write(self.tmp, "notadockerfile.txt", "FROM scratch\n")
        write(self.tmp, "package.json", "{}")
        write(self.tmp, "svc/a/package.json", "{}")

        found = discover_repo_files(self.tmp)

        self.assertEqual(found["dockerfiles"],
                         ["Dockerfile", "svc/a/Dockerfile.prod", "svc/b/app.Dockerfile"])
        self.assertEqual(found["package_jsons"], ["package.json", "svc/a/package.json"])

    def test_paths_are_relative_and_sorted(self):
        write(self.tmp, "z/Dockerfile", "FROM scratch\n")
        write(self.tmp, "a/Dockerfile", "FROM scratch\n")

        paths = discover_repo_files(self.tmp)["dockerfiles"]

        self.assertEqual(paths, ["a/Dockerfile", "z/Dockerfile"])
        self.assertFalse(any(os.path.isabs(p) for p in paths))

    def test_symlinks_are_ignored(self):
        outside = os.path.join(self.tmp, "outside")
        write(outside, "secret.yaml", K8S_POD)
        repo = os.path.join(self.tmp, "repo")
        write(repo, "real.yaml", K8S_POD)
        os.symlink(os.path.join(outside, "secret.yaml"), os.path.join(repo, "link.yaml"))

        self.assertEqual(discover_repo_files(repo)["k8s_manifests"], ["real.yaml"])

    def test_empty_repo(self):
        self.assertEqual(discover_repo_files(self.tmp),
                         {"k8s_manifests": [], "dockerfiles": [], "package_jsons": []})

    def test_oversized_file_is_not_a_manifest(self):
        path = write(self.tmp, "big.yaml", K8S_POD + "# " + "x" * MAX_MANIFEST_BYTES + "\n")
        self.assertFalse(is_k8s_manifest(path))


class RepositoryConfigTest(TempDirTestCase):
    def test_config_fields(self):
        config = get_repository_config("https://github.com/acme/My_Repo.git")

        self.assertEqual(config["repo_name"], "My_Repo")
        self.assertTrue(config["branch"].startswith("security-remediation-"))
        self.assertTrue(config["clone_dir"].startswith("security-remediation-clone-"))
        self.assertNotEqual(config["clone_dir"], config["branch"])
        self.assertRegex(config["image_name"], r"^[a-z0-9][a-z0-9_.-]*$")

    def test_image_name_is_docker_safe_and_unique(self):
        url = "https://github.com/acme/Weird Name!.git"
        first = get_repository_config(url)["image_name"]
        second = get_repository_config(url)["image_name"]

        for name in (first, second):
            self.assertRegex(name, r"^[a-z0-9][a-z0-9_.-]*$")
            self.assertFalse(re.search(r"[A-Z !]", name))
        self.assertNotEqual(first, second)
