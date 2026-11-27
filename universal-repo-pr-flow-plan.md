# Plan: Any-repo scan → JIRA → AI remediation → PR → PR linked to JIRA

## Overview

**Goal.** The user pastes any repository URL in the UI (assumed reachable from this machine). The app then:
1. clones it,
2. scans it,
3. creates JIRA tickets,
4. applies AI remediation,
5. raises a PR against that same repo,
6. attaches the PR to the JIRA tickets.

**Decisions already confirmed with the user**
- Push the remediation branch straight to the target repo using `GITHUB_TOKEN`. If the push fails, report it and do NOT create a PR (no fork fallback).
- JIRA stays one ticket per HIGH/CRITICAL finding, capped at 5. After the PR is raised, add the PR link and a comment to each of those tickets.
- Discover files anywhere in the repo and handle ALL K8s manifests and ALL Dockerfiles found. AI dependency remediation stays Node/npm-only and is skipped cleanly for other ecosystems. A repo with no Dockerfile skips the image scan and CVE fixes.

**What exists today (from code research)**
- Web flow ([`remediator/web/app.py`](remediator/web/app.py) `run_security_scan`, steps 0-21) works for one repo layout only. It looks for `deployment.yaml`, `package.json` and `Dockerfile` at fixed root-level names ([`remediator/config.py`](remediator/config.py) `get_repository_config`).
- The glob-based `find_files_in_repo` in `config.py` is not called by the web app. It is also itself broken: it uses patterns such as `**/*.package.json`.
- Git/PR helpers exist in [`remediator/integrations/git_operations.py`](remediator/integrations/git_operations.py): `create_branch`, `commit_changes`, `push_branch`, `create_pull_request` (uses `gh`), `generate_pr_body`. The web flow never calls them. Only legacy and CLI code does.
- JIRA ([`remediator/integrations/jira_agent.py`](remediator/integrations/jira_agent.py)) creates tickets only. Keys are emitted in progress data but not stored in `scan_results`. Nothing links a PR.
- The "branch" from `generate_unique_branch_name` is currently only used as the clone directory name. It is never a real git branch. Step 0 cleanup removes `cloned_repo`, so `security-remediation-*` clone dirs accumulate.
- The UI shows metrics only. It shows no JIRA keys or PR link.
- The startup log shows `GITHUB_TOKEN`, `JIRA_*` as NOT set, so these are prerequisites for end-to-end runs.

**Approach.** Seven small sub-tasks. Each is independently reviewable and leaves the app working.

```
Task 1 discovery + safe clone
   -> Task 2 multi-file scan
      -> Task 3 multi-file remediation
         -> Task 4 branch/commit/push/PR
            -> Task 5 JIRA PR link
               -> Task 6 UI results
                  -> Task 7 end-to-end verification
```

---

## Sub-task 1: Repo discovery and safe cloning

**Intent.** Stop assuming a fixed layout. Find the relevant files wherever they are. Make the clone step safe for arbitrary user-supplied URLs.

**Expected Outcomes**
- A discovery function returns lists of: K8s manifests, Dockerfiles, `package.json` files (excluding `node_modules`).
- Step 3 reports what was found, with repo-relative paths.
- Clone directories are cleaned per scan (no accumulation), and the real default branch of the repo is recorded for the PR base.
- A malformed or option-like URL (for example one starting with `-`) is rejected before reaching `git`.

**Todo List**
1. Replace/fix `find_files_in_repo` in `config.py` (or add a new discovery function) with correct recursive patterns. Detect K8s manifests by content (`apiVersion` + `kind`) rather than file name, and skip `node_modules`, `.git`, vendor dirs.
2. In `get_repository_config`, drop the hard-coded file names. Keep the env overrides (`DEPLOYMENT_YAML_PATH` etc.) only as optional hints, or remove them if unused.
3. Validate `repo_url` (allow-list of https/ssh git URL forms, no leading `-`) and pass `--` to `git clone`.
4. Clone into a dedicated work dir, separate from the branch name. Clean up that scan's clone at the end and stale ones at the start (glob `security-remediation-*`).
5. Record the default branch after clone (`git symbolic-ref refs/remotes/origin/HEAD`).
6. Update step 3 output in `app.py` to list discovered files.

**Relevant Context**
- `remediator/config.py`: `find_files_in_repo`, `get_repository_config`, `generate_unique_branch_name`
- `remediator/integrations/git_operations.py`: `clone_repository`, `cleanup_cloned_repo`
- `remediator/web/app.py`: steps 0-3 (lines ~254-290), `start_scan` (line ~661) for URL entry point
- `.gitignore` already ignores `security-remediation-*/`

**Status:** [x] done

**Implementation notes (for Sub-task 2 onwards)**
- `config.discover_repo_files(repo_path)` returns `{"k8s_manifests": [...], "dockerfiles": [...], "package_jsons": [...]}`, each a sorted list of **repo-relative** paths. Manifests are detected by content (`yaml.safe_load_all`, any document with `apiVersion` + `kind`, files <= 1 MB). Dockerfiles match `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`. `node_modules`, `.git`, `vendor` and symlinks are skipped. `find_files_in_repo(repo_path, config=None)` is kept for the CLI and returns the first absolute path of each type.
- `get_repository_config` no longer returns `deployment_file` / `package_json_file` / `dockerfile`. It now returns `repo_url, repo_name, branch, clone_dir, image_name`. `clone_dir` is `security-remediation-clone-<rand>` (separate from `branch`, which is still only a generated name and not yet a git branch). The `DEPLOYMENT_YAML_PATH` / `PACKAGE_JSON_PATH` / `DOCKERFILE_PATH` env hints are no longer used by the web flow (they remain in the CLI-only `get_repo_config_from_input`).
- `git_operations.py` gained `validate_repo_url`, `get_default_branch(repo_path)`, `cleanup_stale_clones(base_dir=".", max_age_seconds=3600)`. `clone_repository` validates the URL, uses `git clone -- <url> <dir>`, sets `GIT_TERMINAL_PROMPT=0`, a 600 s timeout, and strips the URL from error text. `start_scan` rejects invalid URLs with HTTP 400. Allowed forms: `https://...`, `ssh://...`, `user@host:path`.
- `run_security_scan`: step 0 removes only `security-remediation-*` dirs older than 1 h (so concurrent scans are safe). Step 2 clones into `config['clone_dir']` (absolute path) and stores `scan_results[scan_id]['default_branch']` (use as the PR `--base` in Sub-task 4). A `finally` block removes this scan's clone, **so Sub-task 4 must create the branch, commit, push and open the PR before the function ends**.
- Step 3 emits `data = {files, k8s_manifests, dockerfiles, package_jsons, detail}` with repo-relative paths. Local variables `manifests`, `dockerfiles`, `package_jsons` (repo-relative lists) are available in `run_security_scan` for Sub-tasks 2/3.
- Temporary shim: `deployment_path`, `package_json_path`, `dockerfile_path` are now the **first** discovered file of each type (absolute path, `''` if none), so steps 4-21 still work unchanged. Sub-tasks 2 and 3 should replace these with loops and then remove the shim. `config['image_name']` is still shared by all scans (`<repo>-scan`); Sub-task 2 must make image tags unique per Dockerfile and per scan.
- Validated with `venv/bin/python` (no bare `python` on this machine): `py_compile`, discovery on `security-remediation-55744r` (finds `deployment.yaml`, `Dockerfile`, `package.json`; default branch `main`), a synthetic nested repo (multi-doc YAML, `.yml`, Helm template and plain YAML excluded, `node_modules`/`vendor`/`.git` skipped), accept/reject URL cases, stale-clone cleanup, and `POST /api/scan` with `--upload-pack=x` returns 400.

---

## Sub-task 2: Scan every discovered asset

**Intent.** Make the scan steps work on all discovered files, not one.

**Expected Outcomes**
- Every K8s manifest is scanned. Each finding carries the repo-relative file it came from.
- Every Dockerfile is built with its own directory as build context, and each image is CVE-scanned. If there is no Dockerfile, the image scan and CVE fixes are skipped with an info step (no error).
- Build failures in the *initial* scan are reported clearly, not swallowed (today `docker build` output is discarded at line ~312).
- SAST/secrets unchanged (already whole-repo).

**Todo List**
1. Loop `scan_k8s_config` over all manifests and tag each finding with its file.
2. Loop build+`scan_image` over Dockerfiles, with unique image tags per Dockerfile. Tag CVE findings with the Dockerfile.
3. Check the `docker build` return code and surface failure as an info/warning step.
4. Make sure `combine_findings` preserves the file attribution (needed for JIRA and the PR body).

**Relevant Context**
- `remediator/scanners/scanner.py` (`scan_k8s_config`, `summarize_findings`), `image_scanner.py`, `remediator/findings.py`
- `app.py` steps 4-5 (lines ~292-324)

**Status:** [x] done

**Implementation notes (for Sub-task 3 onwards)**
- `config.get_repository_config`: `image_name` is now unique per scan (`<sanitised-repo>-scan-<rand6>`, lower-case docker-safe), so concurrent scans cannot collide.
- `app.py` new helpers: `build_docker_image(repo_dir, dockerfile_rel, tag)` (runs `docker build -f <dockerfile> -t <tag> <dockerfile's dir>`, returns the CompletedProcess), `docker_failure_reason(stderr)` (short reason, registry-login hint, never raw stderr), `remove_docker_images(tags)` (best-effort `docker rmi -f`, called in the `finally` for every tag in the `built_images` list).
- Step 4 loops over all `manifests`. Each finding dict gets `file` = repo-relative manifest path. Manifests that fail to scan emit an info step and are skipped. Set `scanned_manifests` holds the ones that scanned OK.
- Step 5 loops over all `dockerfiles`. Tag is `f"{config['image_name']}-{index}"` (index in the `dockerfiles` list). Each CVE finding gets `file` (repo-relative Dockerfile) and `image` (tag). A failed build (return code != 0) emits an info step with a short reason (tail of stderr only in the server log) and continues. Set `scanned_dockerfiles` holds the ones that built and scanned. No Dockerfile -> info step "skipping image scan", no error. Step data keys (`count`, `cve_count`, `total_findings`, `detail`) are unchanged and are aggregated across files.
- `findings.py`: `normalize_k8s_findings` now emits `file`; `normalize_cves` emits `file` and `image`. SAST/SECRET already had `file`. So `all_findings` items for MISCONFIG/CVE carry the repo-relative file (use it for JIRA descriptions, per-file remediation and the PR body).
- Temporary shim still in place for Sub-task 3 (remove it there): `first_manifest`, `first_dockerfile` (repo-relative or None), `first_k8s_findings`, `other_k8s_findings`, `first_cve_findings`, `other_cve_findings`. Steps 13-20 remediate/rebuild only the first manifest and first Dockerfile and are fed only that file's findings. The findings of the other files are added back unchanged into `new_k8s_findings` / `new_cve_findings` in steps 19-20 so before/after metrics stay consistent. The step 19 rebuild tag is `f"{config['image_name']}-0-fixed"` (also in `built_images`). When Sub-task 3 loops, use per-Dockerfile tags such as `f"{image_name}-{index}-fixed"` and append them to `built_images`.
- Step 20 re-scan still handles only the first manifest (`deployment_path`); `scanned_manifests` / `scanned_dockerfiles` can be used to skip assets that could not be scanned initially.
- Validated with `venv/bin/python`: `py_compile`; a driver script (clone/Bob/JIRA stubbed) on a synthetic repo with 2 manifests and 3 Dockerfiles (one failing build) gave attributed findings for both manifests, a CVE finding attributed to `svc/b/Dockerfile.ok`, an info step for the failed build, and all images removed afterwards; and on `security-remediation-55744r` (1 manifest finding, 1040 CVEs, files `deployment.yaml` / `Dockerfile`).

---

## Sub-task 3: Remediate every discovered asset

**Intent.** Apply AI fixes per file, keep Node/npm dependency fixes limited to Node projects, and keep the safety nets (validation, revert on failure).

**Expected Outcomes**
- Each K8s manifest is remediated and validated individually. A bad AI output for one file does not block the others.
- Each Dockerfile is remediated and rebuilt, and is reverted if its rebuild fails (existing behaviour, now per file).
- `package.json` remediation runs per `package.json` found, and is skipped cleanly when none exist (Python/Java/Go repos).
- Metrics before/after aggregate across all files.
- The list of files actually changed is kept (needed by Task 4).

**Todo List**
1. Refactor steps 13-19 in `run_security_scan` into per-file helpers (small functions in `app.py` or a new module).
2. Call `generate_remediation` per manifest / `package.json`, instead of once with single inputs.
3. Per Dockerfile: `generate_dockerfile_remediation`, rebuild with its own context, revert on failure.
4. Accumulate `files_updated` as repo-relative paths.
5. Re-scan all assets in step 20. Aggregate metrics in step 21.

**Relevant Context**
- `remediator/remediation/remediation.py`, `dockerfile_remediation.py` (UBI registry rewrite already done), `source_remediation.py`
- `remediator/validation/validator.py`, `dependency_validator.py`
- `app.py` steps 13-21 (lines ~392-645)

**Status:** [x] done

**Implementation notes (for Sub-task 4 onwards)**
- The first-file shim is gone (`deployment_path` / `package_json_path` / `dockerfile_path`, `first_*` / `other_*` findings, the `-0-fixed` tag). Steps 13-20 loop over `manifests`, `package_jsons` and `dockerfiles`. All paths are repo-relative; absolute paths are built with `os.path.join(clone_dir, rel)`.
- **`files_updated`** (sorted, repo-relative, de-duplicated) is a local variable in `run_security_scan` and is stored in `scan_results[scan_id]['files_updated']` right after step 19 (before the re-scan). It holds only files whose change was kept: manifests and `package.json` files that passed validation, Dockerfiles whose rebuild succeeded, and source files from `apply_source_fixes` (step 15). Reverted files are removed from it. Sub-task 4 should `git add` exactly these paths. Nothing is written as `.bak`; `git status` in a test clone showed only the intended files.
- **The clone is deleted** in the `finally` block at the end of `run_security_scan` (`cleanup_cloned_repo(clone_dir)` followed by `remove_docker_images(built_images)`). Branch, commit, push and PR must happen after step 21 and before that `finally`. `clone_dir` (absolute) and `scan_results[scan_id]['default_branch']` are available there. A fatal exception jumps to the `except`, so check `scan_results[scan_id]['status'] == 'complete'` before creating a PR.
- Step 13 (manifests): per manifest, `generate_remediation(findings_json, original_yaml, None)` with only that manifest's `MISCONFIG` findings (`finding['file'] == manifest`). Manifests with no findings are skipped. Step 13 (package.json): per file, `generate_remediation(findings_json, None, original_json)`. Helper `package_json_findings` selects findings whose `file` is that package.json (none exist today) plus the CVEs whose `package` is declared in its dependency sections (deduplicated by id+package, max `MAX_PACKAGE_FINDINGS` = 20). No package.json, or none with matching findings, makes the loop a no-op (Python/Java/Go repos). OS-package CVEs are never sent to npm remediation. SAST/SECRET findings still go only to `apply_source_fixes` (unchanged).
- Step 14 writes each fixed file (plus a trailing newline) and skips a reply identical to the original. Step 17 validates each file: manifests with `validate_yaml` plus the new public `config.is_k8s_manifest` (renamed from `_is_k8s_manifest`; rejects a reply that is valid YAML but not a manifest); package.json with `validate_package_json` plus `check_fixed_package_json` per file. A file that fails is restored to its original text, removed from `files_updated` and reported with an info step. Step 17 no longer aborts the scan with an `error` status; it always ends with `success` and data `{'validated': [...], 'reverted': [{'file', 'reason'}]}` (the UI only shows the message/`detail`, so it is unaffected).
- Steps 18/19 (Dockerfiles): only Dockerfiles that were scanned and have CVE findings are remediated, using only the findings with `file == dockerfile` (first 10 as before). Each rebuild uses its own context and the tag `f"{image_name}-{index}-fixed"` (appended to `built_images`, so the `finally` removes it). A failed rebuild restores the original Dockerfile, keeps that file's CVEs in the "after" count and emits an info step. A successful one is added to `files_updated` and its image is re-scanned. Unchanged Dockerfiles keep their original CVE findings in the "after" count, so no "findings added back" workaround remains. The UBI rewrite in `dockerfile_remediation.py` is untouched.
- Error isolation: every per-file read / AI call / write / validate / build is in its own `try`/`except`. Details go to the server log only; the UI gets an info step such as `<file> left unchanged: remediation failed (see server log)`. No finding text, URL or secret is logged.
- Step 20 re-scans every manifest in `scanned_manifests` (a failed re-scan keeps that manifest's old findings). Images were already re-scanned in step 19. SAST/secrets are re-scanned as before. Step 21 metrics keep the same keys (`kubernetes`, `cve`, `sast`, `secrets`, `total`, `advisory`).
- Validated with `venv/bin/python`: `py_compile`, and a driver (clone, Bob, JIRA and image scan stubbed; real trivy for K8s/SAST/secrets and real `docker build`) on a synthetic repo with 2 manifests, 2 package.json and 2 Dockerfiles. One manifest reply was invalid YAML (reverted), one package.json call raised (left unchanged), one Dockerfile reply had an unbuildable base image (rebuild failed, reverted). Result: scan `complete`, `files_updated = [k8s/a/deploy.yaml, svc1/Dockerfile, svc1/package.json]`, `git status` in the clone showed exactly those three files modified, each remediation call got only its own file's findings, and the clone and images were removed. A Python-only repo (no manifests, Dockerfile or package.json) completed cleanly with zero metrics.

---

## Sub-task 4: Branch, commit, push and raise the PR

**Intent.** Deliver the fixes back to the user's repo as a PR. This is the main missing capability.

**Expected Outcomes**
- A new step after metrics creates a real git branch in the clone, commits only the files that remediation changed, pushes to `origin`, and opens a PR against the repo's default branch.
- PR body is built from the actual before/after metrics and the findings addressed, including JIRA keys.
- If nothing changed, no branch and no PR; the step reports "no changes".
- If `GITHUB_TOKEN` is missing or the push is denied, the step reports the reason and no PR is created. The scan itself still completes.
- The token is never written to logs, URLs or the UI.

**Todo List**
1. Add a "create PR" step constant and wire it after STEP_METRICS (adjust the UI step list accordingly in Task 6).
2. Use `create_branch`, then stage only the changed files (no `git add .`). This avoids committing stray files such as `.bak`. Then `commit_changes` and `push_branch`.
3. Authenticate the push with the token without embedding it in the remote URL or process args (for example a credential/askpass env or `http.extraHeader` via environment).
4. Call `create_pull_request` with `--base <default branch>`, and make PR URL parsing robust for repo URLs with a trailing slash or `.git`.
5. Update `generate_pr_body` so it reflects what was really changed (it currently hard-codes "Updated vulnerable dependencies", "Fixed Kubernetes...") and accepts JIRA keys and per-category metrics.
6. Handle and report errors (no token, push rejected, `gh` missing, non-GitHub URL) without exposing secrets.
7. Store `pr_url` in `scan_results[scan_id]`.

**Relevant Context**
- `remediator/integrations/git_operations.py` (all PR helpers already exist but are unused by the web flow)
- `remediator/legacy/app_new.py` line ~217 and `remediator/cli.py` line ~290: previous usage examples of `create_pull_request`
- Security rules: no secrets in logs or URLs, input validation

**Status:** [x] done

**Implementation notes (for Sub-task 5 onwards)**
- New step `STEP_PR = 22` ("Pull Request", added to `STEPS`, so the template already renders it; `app.js` needs no change for the row itself). It is run by `raise_pull_request(...)` in `app.py`, called after step 21 inside the `try` of `run_security_scan` and **before** the `finally` that deletes the clone, and before `status = 'complete'` is set. `raise_pull_request` never raises: everything is caught, logged server-side (token scrubbed) and reported as an `info` step with a short safe message. The scan always ends `complete`.
- **`scan_results[scan_id]` fields** (set by `set_pr_result`): `pr_url` (str or `None`), `pr_status` and `pr_message` (short, safe text). `pr_status` values: `created`, `no_changes`, `no_token`, `unsupported_host`, `commit_failed`, `push_failed`, `failed` (branch pushed but `gh` failed). The step-22 progress event carries `data = {'pr_url', 'detail'}`; status is `success` only when a PR exists, otherwise `info`.
- **`jira_keys`**: a local list in `run_security_scan` (step 12), stored as `scan_results[scan_id]['jira_keys']` (list of strings, `[]` if JIRA is not configured) right after step 12, so it is also present if the scan later fails. **Hook for Sub-task 5:** in `raise_pull_request`, in the success path directly after `set_pr_result(scan_id, 'created', ...)` (or in `run_security_scan` right after the `raise_pull_request(...)` call, when `scan_results[scan_id]['pr_url']` is set). Both are before the clone is removed and neither is inside a path that can fail the scan. Wrap the linking in its own try/except and add a new step constant (`STEP_JIRA_LINK = 23`) plus a `STEPS` entry. `jira_keys` is also passed to the PR body.
- `git_operations.py` additions (all backward compatible): `validate_branch_name` (allow-list `^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$`, no `..`, `//`, trailing `/`, `.`, `.lock`; applied in `create_branch`, `push_branch`, `create_pull_request` and for `base`), `parse_github_repo(url)` -> `"owner/repo"` (https with credentials/trailing slash/`.git`, `ssh://git@github.com/o/r.git`, `git@github.com:o/r.git`; raises `UnsupportedRepositoryHost` for any other host, including look-alikes such as `github.com.evil.com`), `scrub_secrets(text, *secrets)`, `_github_auth_env`.
- `commit_changes(repo_path, message=..., paths=None)`: with `paths` it runs `git add -- <paths>` and `git commit -m ... -- <paths>` (only those files; stray/untracked/other modified files are left out; rejects absolute paths, `..` and an empty list). Without `paths` it keeps the old `git add .` behaviour for CLI/legacy callers.
- `push_branch(repo_path, branch, github_token=None)`: for an https `github.com` origin the token goes only in the process **environment** as `GIT_CONFIG_COUNT/KEY/VALUE` with `http.https://github.com/.extraheader` = `Authorization: Basic base64(x-access-token:<token>)` (scoped to github.com, so never sent elsewhere), plus `GIT_TERMINAL_PROMPT=0`. It is never in the remote URL, `.git/config` or the arguments. ssh and non-GitHub remotes use the machine's ssh/git config. 300 s timeout; error text is scrubbed.
- `create_pull_request(..., github_token=None, base=None)`: uses `parse_github_repo`, adds `--base <base>` when given, passes the token only as `GH_TOKEN` (plus `GH_PROMPT_DISABLED=1`), 120 s timeout, clear errors for a missing `gh` and scrubbed `gh` stderr. The non-GitHub case raises `UnsupportedRepositoryHost`, which the web step turns into an `info` step.
- `generate_remediation_pr_body(files_updated, metrics, findings=None, jira_keys=None)` (new; the old `generate_pr_body` is untouched for CLI/legacy): lists the changed files, a before/after/fixed table from the real `metrics` (kubernetes, cve, sast, secrets, total, only the categories present), the findings located in changed files (sorted by severity, max 15, markdown-escaped), JIRA keys, and a review checklist. No hard-coded claims.
- PR title/commit message: "Security remediation: fix vulnerabilities and misconfigurations". Branch = `config['branch']` (`security-remediation-<rand6>`), base = `scan_results[scan_id]['default_branch']`.
- Not done on purpose: no UI rendering of `pr_url` / `jira_keys` (Sub-task 6); `gh` is not installed on this machine, so a real PR run needs `gh` (Sub-task 7).
- Validated with `venv/bin/python` and no real GitHub/remote: `py_compile`; helper tests on a local bare repo (only `files_updated` committed while a modified file and an untracked file stayed out, branch exists on the bare remote, legacy `git add .` path still works, push to a removed remote raises without the fake token, token absent from push args, remote URL and `.git/config`, auth header only for https github.com remotes); slug parsing for all URL forms plus rejected hosts; `create_pull_request` with a stubbed `subprocess.run` (`--repo`, `--head`, `--base`, token only in `GH_TOKEN`, scrubbed errors, missing `gh`); PR body content. End-to-end `run_security_scan` with stubs (local bare origin, Bob/JIRA/scanners/`create_pull_request` stubbed) for no token, no changes, successful PR (branch pushed, diff = only `k8s/deploy.yaml`, `base=main`, `jira_keys=['SEC-7']`), push failure (no PR attempt), `gh` failure after push, and a non-GitHub URL (no branch created). All ended `complete`, with a fake token absent from logs and `scan_results`, and clones removed.

---

## Sub-task 5: Attach the PR to the JIRA tickets

**Intent.** Close the loop so each ticket tracks its remediation.

**Expected Outcomes**
- Ticket keys created in step 12 are kept in `scan_results[scan_id]` and in the run's state.
- After the PR is created, each ticket gets a remote link to the PR and a comment with a short summary (what was fixed, metrics, PR URL).
- Failure to link one ticket does not fail the scan, and is logged.
- With JIRA not configured, the step is skipped with an info message (as today).

**Todo List**
1. Add `link_pr_to_ticket(key, pr_url, summary)` to `jira_agent.py` using the JIRA client's remote link and comment calls, with the same "returns None / logs on failure" style as `create_jira_ticket`.
2. Include the file and finding details in the ticket description, so tickets match the PR content.
3. After Task 4, loop over `jira_keys` and call the new function.
4. Persist `jira_keys` and the linking result in `scan_results`.

**Relevant Context**
- `remediator/integrations/jira_agent.py` (`create_jira_ticket`, module-level `jira` client)
- `app.py` step 12 (lines ~378-392), `JIRA_SEVERITIES`

**Status:** [x] done

**Implementation notes (for Sub-task 6 onwards)**
- `jira_agent.py`: `link_pr_to_ticket(key, pr_url, summary)` validates `key` (`^[A-Z][A-Z0-9_]+-\d+$`) and `pr_url` (https, host present, no embedded credentials, no whitespace/control chars), then calls `jira.add_simple_link(key, {url, title})` and `jira.add_comment(key, summary + PR url)`. Both are always attempted; it returns `True` only if both succeed, `False` otherwise (including JIRA not configured or invalid input). It never raises. Errors are logged as the exception class name (plus HTTP status) only, never the message, because JIRA/requests errors can echo URLs or auth headers. `is_jira_configured()` is new. The startup failure print was also reduced to the exception class name.
- `create_jira_ticket(finding, repo_url=None)` (backward compatible): the description is now built by `build_ticket_description` from an allow-list of fields (Repository, Type, Severity, ID, Title, Details, File, Image, Package, installed/fixed version, Resource), single-line and length-limited, with URL credentials stripped from the repo URL. The raw finding dict is no longer dumped, and the SECRET finding never holds the value. Step 12 now passes `repo_url`.
- `app.py`: new `STEP_JIRA_LINK = 23` ("JIRA Links", added to `STEPS`, so the template renders the row). `link_pr_to_jira_tickets(scan_id, pr_url, jira_keys, metrics, files_updated)` runs right after `raise_pull_request(...)` and before `status = 'complete'`, inside the clone's lifetime. It never raises, and one ticket failing does not stop the others. Comment text comes from `build_jira_summary(metrics, files_updated)`: before -> after (fixed) per category, up to 10 changed files, PR URL.
- **`scan_results[scan_id]` fields**: `jira_keys` (list, unchanged from Sub-task 4), `jira_links` (`{key: True/False}`; `{}` when nothing was attempted) and `jira_link_message` (short safe text). No credentials and no JIRA base URL are stored. Sub-task 6 should build ticket links from `JIRA_URL` itself (expose it via a safe config/status field), as `browse/<KEY>`.
- **Step 23 progress event**: `data = {'links': {key: bool}, 'detail': '(SEC-1, SEC-2)'}`. Status `success` if at least one ticket was linked, otherwise `info`. Info messages: no PR raised, no tickets, JIRA not configured, or all links failed. The `running` event "Linking the pull request to JIRA tickets..." is only emitted when linking is actually attempted.
- Validated with `venv/bin/python` (no real JIRA/GitHub): `py_compile`; a fake JIRA client checked call arguments, rejected invalid keys/URLs (no calls made), failure isolation (a raising `add_simple_link` still attempts the comment, no leaked message in output), the not-configured path, and that a SECRET finding with extra `Match`/`secret` fields never reaches the description (nor URL credentials). End-to-end `run_security_scan` with stubs: PR + 3 tickets with `SEC-2` failing (`jira_links = {SEC-1: True, SEC-2: False, SEC-3: True}`, other tickets still linked), no token (no PR, no link calls, info step), JIRA not configured, no tickets, and a linker that raises. All ended `complete`; no secrets in logs; temp dirs removed.

---

## Sub-task 6: Show results in the UI

**Intent.** Make the outcome visible to the user.

**Expected Outcomes**
- Step list includes the new PR and JIRA-link steps.
- The result view shows the PR link and the JIRA ticket keys (as links when `JIRA_URL` is known).
- A clear message when no PR was raised (no changes / no token / push denied).

**Todo List**
1. Add the new steps to the step list in the template and `app.js`.
2. Render `pr_url` and `jira_keys` from the status response.
3. Expose a browse URL for tickets (from `JIRA_URL`) without exposing credentials.

**Relevant Context**
- `remediator-ui/static/js/app.js` (polling and `METRIC_CARDS` rendering), `remediator-ui/templates/index.html`
- `app.py` `get_scan_status` (line ~685) returns `scan_results[scan_id]`

**Status:** [x] done

**Implementation notes (for Sub-task 7)**
- Steps 22 (Pull Request) and 23 (JIRA Links) already come from `STEPS` in `app.py`; the template renders rows from it and `updateStep` maps `progress.step` to `.step[data-step=N]`, so they show success/info/error and `data.detail` with no JS change. The step rows are the only live view of those two steps; the results panel is shown after the scan completes.
- Backend (only change): `get_jira_base_url()` in `app.py` returns `https://<host><path>` from `JIRA_URL` (trailing `/` stripped) only if JIRA is configured (`is_jira_configured()`), the scheme is https, a host exists, and there are no embedded credentials or whitespace/control chars. Otherwise `None`. Step 12 stores it as `scan_results[scan_id]['jira_base_url']` only when not `None` (the key is absent otherwise). No email/token is ever stored.
- UI: new "Pull Request & JIRA" section (`#deliverySection` / `#deliveryBody` in `index.html`, styles at the end of `style.css`). `showResults(metrics, result)` now receives the full status JSON and calls `showDelivery(result)`; metric cards and advisory behaviour are unchanged. Everything is built with `createElement`/`textContent` (no `innerHTML` anywhere). Links go through `safeHttpsUrl` (must start with `https://`, no whitespace/control chars, no credentials), then `target="_blank"` and `rel="noopener noreferrer"`.
- Result states: PR created -> clickable `pr_url`; no PR -> `pr_message` as text (covers `no_changes`, `no_token`, `unsupported_host`, `commit_failed`, `push_failed`, `failed`), with a generic fallback; `default_branch` ("Base branch: ...") and `files_updated` (repo-relative, in `<code>`) shown when present; JIRA keys link to `<jira_base_url>/browse/<KEY>` when the key matches `^[A-Z][A-Z0-9_]+-\d+$` and the base URL is valid, otherwise plain text; per-key "pull request linked / link failed" from `jira_links`, plus `jira_link_message`; "No JIRA tickets were created." when `jira_keys` is empty. A scan that ends in `error` behaves as before (alert, no result view).
- Validated: `node --check app.js`; `venv/bin/python -m py_compile remediator/web/app.py`; Flask test client (index contains rows 22/23 and `#deliveryBody`; `get_jira_base_url` accepts https with/without trailing slash or path, rejects http, credentials, ftp, empty or JIRA not configured; status JSON carries `pr_url`, `jira_keys`, `jira_links`, `jira_base_url`); a node script running `showResults` against a stubbed DOM (setting `innerHTML` throws) for PR+JIRA ok, no PR/no token, PR without base URL, hostile values (`javascript:` PR url, `<img onerror>` text, credentials in base URL, `<b>` key) and missing fields: no unsafe link and every hostile value shown as text. `grep` finds no `innerHTML`/`insertAdjacentHTML`/`outerHTML`/`document.write` in `app.js` or `index.html`. No server was started; temp test files were removed.
- Not done: no browser (visual) check. Run the UI once in Sub-task 7 to confirm the layout.
- **For Sub-task 7:** needed env vars are `BOB_API_KEY` (remediation), `GITHUB_TOKEN` (repo write; also needs `gh` installed), `JIRA_URL` (must be https for ticket links), `JIRA_EMAIL`, `JIRA_API_TOKEN` and optional `JIRA_PROJECT` (default `SEC`). Run with `HOST=127.0.0.1 venv/bin/python -m remediator.web.app` (port `PORT`, default 8000). UI scenarios to check: (1) PR + linked tickets (links open in a new tab), (2) no `GITHUB_TOKEN` (message `no_token`, tickets listed as text/links without link status), (3) no JIRA env (no ticket links, "No JIRA tickets were created."), (4) JIRA configured with `http://` URL (keys shown as text), (5) repo without changes (`no_changes`), (6) non-GitHub URL (`unsupported_host`), (7) push denied (`push_failed`), (8) invalid URL (HTTP 400 alert). The status JSON also lists `jira_base_url` only when JIRA is configured.

---

## Sub-task 7: End-to-end verification

**Intent.** Prove the flow works on repos with different layouts, not just the sample repo.

**Expected Outcomes**
- Scan on the existing sample Node repo: PR created, JIRA tickets linked.
- Scan on a repo with no Dockerfile or K8s manifests (for example a small Python repo): completes without errors, skips the image scan, and only raises a PR if something changed.
- Scan on a repo with manifests/Dockerfile in subfolders or several of them: all are scanned and fixed.
- Failure paths verified: missing token, push denied, JIRA not configured, invalid URL.

**Todo List**
1. Set `GITHUB_TOKEN` (repo write scope) and JIRA env vars in `.env` (never commit). Confirm `gh` is installed and authenticated via `GH_TOKEN`.
2. Run the scenarios above using the UI. Check PR content and JIRA links.
3. Add focused unit tests for discovery, URL validation and PR-body generation (the repo has no test suite today, so keep this small).
4. Update README: the flow, required env vars and prerequisites.

**Relevant Context**
- `README.md`, `.env` (key names only), `requirements.txt`

**Status:** [x] done (offline part). The live verification items listed below are still for the user to run.

**Implementation notes**
- Scope was restricted to offline work: no real push/PR/JIRA/GitHub token use, no remote scans, and `.env` was not read (only the variable names were listed). Nothing was committed or staged.
- **Tests:** `tests/` (stdlib `unittest`; pytest is not installed, so no new dependency). Run with `venv/bin/python -m unittest discover -s tests -t .` (82 tests, ~7 s, all pass; also clean with `-W error::ResourceWarning`). `tests/helpers.py` is imported first by `tests/__init__.py`: it turns `load_dotenv` into a no-op (so `.env` is never read), removes `JIRA_*`, `BOB_*`, `GITHUB_*`, `GH_*` from the environment and ignores global git config. Files: `test_discovery.py` (discovery, config), `test_git_operations.py` (URL/branch validation, clone args and credential scrubbing, `parse_github_repo`, selective commit and token-free push against a local bare origin, `create_pull_request` args with stubbed `subprocess.run`), `test_pr_body.py`, `test_jira_agent.py` (description without secret values, `link_pr_to_ticket` validation and failure isolation with a fake client, not-configured path), `test_web_app.py` (`get_jira_base_url`), `test_scan_flow.py`.
- **Offline end-to-end (in `test_scan_flow.py`):** real `run_security_scan` with scanners, docker, Bob, `gh` and JIRA stubbed and a local bare repo as origin, each test in its own temp working directory. Scenarios: PR created + 3 tickets linked (diff is exactly the remediated files, base `main`, body numbers match the metrics); one ticket failing to link; no token; no changes; push denied; non-GitHub URL; JIRA not configured; repo with no manifest/Dockerfile (image scan skipped, completes); nested and multiple assets (aggregated metrics, all images removed). In every case the scan ends `complete`, the clone is removed and neither the fake token nor a fake Bob key appears in `scan_results` or the logs. `POST /api/scan` with invalid URLs returns 400 without starting a thread, plus 404 for an unknown scan and the index renders rows 22/23. A mutation check (commit with `paths=None`) made the PR test fail, so the suite does detect committing stray files.
- **Bugs found by the tests and fixed:** `$` in `_ISSUE_KEY` (`jira_agent.py`) and `_BRANCH_NAME_PATTERN` (`git_operations.py`) also matched before a trailing newline (`"SEC-1\n"`, `"main\n"` were accepted). Both now end with `\Z`.
- **README rewritten:** flow, tools and env vars (`BOB_API_KEY`, `GITHUB_TOKEN`, `JIRA_*`, `HOST`/`PORT`, `LOG_LEVEL`, feed paths), failure behaviour table, UBI note (`registry.access.redhat.com`, no login), how to run the tests, live checklist. Outdated content was removed: OpenAI references, the fixed `deployment.yaml` / `cloned_repo/` names, "Links to remediation PR (optional)", the old 15-step list and port 5000.
- **Findings for the user (not changed):** (1) `.env` is **tracked** in git (`git ls-files` lists it, and it is modified), so `.gitignore` does not protect it. Run `git rm --cached .env` yourself, and consider rotating any secret that was ever committed. (2) The `Dockerfile` copies `.env*` into the image. (3) The `Dockerfile` does not set `HOST`, so the container binds to `127.0.0.1` and a published port may not be reachable; the Docker run path was not tested.

**Still to run live by the user** (needs real GitHub/JIRA/Bob/docker/trivy/gh; see the README checklist)
1. Setup: `gh`, `docker`, `trivy`, `gitleaks`, `bob` installed; `.env` has `BOB_API_KEY`, `GITHUB_TOKEN` (write access), `JIRA_*`.
2. Sample Node repo: PR created, only remediated files changed, body correct, JIRA tickets (max 5) have the remote link and comment.
3. Python-only repo: completes cleanly, image scan skipped, PR only if something changed.
4. Nested / multiple manifests, Dockerfiles and `package.json`: all scanned and fixed, correct relative paths in the commit.
5. Failure paths against the real services: empty token, read-only token (`push_failed`), non-GitHub URL, JIRA removed, `JIRA_URL` with `http://`, nothing to fix.
6. UI look and feel in a browser (links open in a new tab, layout of the "Pull Request & JIRA" section), real `gh pr create` output parsing, and cleanup of test branches/PRs, clones and images.

---

## Open risks / notes
- The token needs write access to the target repo. Pushes to repos it cannot write to will report an error (by design, per decision above).
- `gh` CLI must be installed on the host. It is not in `requirements.txt`.
- Concurrent scans share docker image names and the clone cleanup. Task 1 should make these unique per scan.
- Only GitHub is supported for PRs (existing `create_pull_request` limitation). Other hosts report "unsupported" after the scan.

---

## Update: GitHub CLI removed

The PR is now created through the GitHub REST API (`POST /repos/{owner}/{repo}/pulls`, `urllib` from the standard library), authenticated with `GITHUB_TOKEN`. `gh` is no longer needed on the host or in the Docker image. This supersedes the earlier notes in this file that mention `gh`, `GH_TOKEN` and `gh pr create`. `create_pull_request` keeps its signature. Reason: a live scan pushed the branch but failed with "GitHub CLI (gh) is not installed".
