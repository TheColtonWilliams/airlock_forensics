# Setting up the GitHub repository

Steps for the repository owner. Tasks 0.1 (create the public repository) and 0.8 (protect
`main`). An automated builder cannot do these: they need the owner's GitHub account. Everything
the steps use is already in this repository.

## 1. Create the empty repository (task 0.1)

1. Sign in to GitHub with the account or organisation that will own the project.
2. Open <https://github.com/new>.
3. Repository name: **`airlock`**. Description:
   "AIRLOCK: Air-gapped, Isolated, Read-only, Locked-down, Offline Case Kit. A bootable,
   locked-down USB forensic workstation built from Ubuntu 24.04 as code."
4. Visibility: **Public**.
5. Leave **every** "Initialize this repository" box empty: no README, no .gitignore, no licence.
   The repository already has all three (the licence is Apache-2.0, decision log 2026-11-15).
6. Press **Create repository**.

Or with the GitHub CLI, from the checkout:

```
gh repo create <owner>/airlock --public \
  --description "AIRLOCK: Air-gapped, Isolated, Read-only, Locked-down, Offline Case Kit"
```

## 2. Push the existing history

From the root of the local checkout:

```
git remote add origin https://github.com/<owner>/airlock.git
git push -u origin main
```

If `origin` already exists, use `git remote set-url origin https://github.com/<owner>/airlock.git`.

## 3. Repository settings

In **Settings**:

* **General, Features:** Issues on; Wikis off (documentation lives in `docs/`); Discussions
  optional.
* **General, Pull Requests:** allow squash merging and rebase merging; turn off merge commits
  (the branch rule below asks for a linear history); turn on "Automatically delete head branches".
* **Actions, General:** "Allow all actions and reusable workflows" is not needed: choose "Allow
  <owner>, and select non-<owner>, actions" and allow `actions/checkout@*`,
  `actions/setup-python@*`, `actions/upload-artifact@*`, `actions/download-artifact@*`. Workflow
  permissions: **Read repository contents** (the release workflow asks for more itself).
* **Code security:** turn on Dependabot alerts and secret scanning. Private vulnerability
  reporting is turned on by the script in step 5 (SECURITY.md points to it).

## 4. Let the workflows run once

Push any small change through a pull request (or run each workflow with **Run workflow** under
**Actions**). GitHub offers a check as "required" only after it has seen it run. The checks are:

* `lint (scripts/lint.sh)`, `unit tests (pytest)`, `functional tests (root, loop devices)`
  from [lint.yml](../../.github/workflows/lint.yml);
* `PSScriptAnalyzer` and the three `fetch-assets.ps1 on ...` jobs from
  [windows.yml](../../.github/workflows/windows.yml);
* the image jobs from [build.yml](../../.github/workflows/build.yml), which take hours without KVM.

## 5. Protect `main` (task 0.8)

With the GitHub CLI logged in as an admin of the repository (`gh auth login`):

```
scripts/setup-branch-protection.sh --dry-run      # print what it will set
scripts/setup-branch-protection.sh                # apply (asks you to type yes)
```

It makes `main` accept changes only through a pull request with every lint, unit, functional and
Windows check green; blocks force pushes and deletion; asks for a linear history; applies the
rules to admins too; and turns on private vulnerability reporting. Options:

* `--reviews 1` once there is a second maintainer (a single owner cannot approve their own pull
  request, so the default is 0 approvals but a pull request is still required);
* `--with-build` to also require the image build and QEMU jobs (only with a fast KVM runner);
* `--repo OWNER/NAME` if `gh` cannot tell which repository this is.

## 6. Release secrets (before the first tag)

See [release-process.md](../release-process.md), "One-time setup": the `MANIFEST_SIGNING_KEY`
secret, the `MANIFEST_SIGNING_PUBKEY` variable, and the optional `AIRLOCK_BUILD_RUNS_ON` and
`AIRLOCK_LICENCE_REVIEW_DONE` variables.

## Done when

* the repository is public at `https://github.com/<owner>/airlock` with the full history;
* the branch rule shows on **Settings, Branches** for `main`;
* a test pull request cannot be merged until its checks pass.

Then set tasks 0.1 and 0.8 to `done` in [build-plan.md](../build-plan.md).
