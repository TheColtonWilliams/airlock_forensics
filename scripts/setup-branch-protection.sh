#!/usr/bin/env bash
# Protect the main branch of the AIRLOCK GitHub repository (task 0.8): changes land only through
# a pull request, and only when the CI checks are green. Also turns on GitHub private
# vulnerability reporting, which SECURITY.md points to.
#
# Run it once, by the repository owner, after the first push and after the workflows have run at
# least once (GitHub only offers a check as "required" once it has seen it). Needs the GitHub CLI
# (gh), logged in with admin rights on the repository: gh auth login.
#
# Usage: scripts/setup-branch-protection.sh [options]
#   --repo OWNER/NAME   repository (default: the one gh finds for this checkout)
#   --branch NAME       branch to protect (default: main)
#   --reviews N         approving reviews a pull request needs (default 0: a single owner cannot
#                       approve their own pull request; set 1 or more once there are reviewers)
#   --with-build        also require the image build and QEMU jobs (build.yml). They take hours
#                       without KVM, so they are not required by default.
#   --no-vuln-reporting do not turn on private vulnerability reporting
#   --dry-run           print the API calls and the JSON body; change nothing
#   --yes               do not ask before changing the repository settings
#   -h, --help          this help
#
# Exit status: 0 done (or printed with --dry-run); 1 a step failed (one line says which and what
# to do); 2 bad usage.
# Test: tests/unit/test_repo_meta.py
set -euo pipefail

prog="setup-branch-protection"
repo=""
branch="main"
reviews=0
with_build=0
vuln_reporting=1
dry_run=0
yes=0

# Check names are the job names in .github/workflows/*.yml (matrix jobs expanded).
# tests/unit/test_repo_meta.py fails when this list and the workflows drift apart.
REQUIRED_CHECKS=(
  "lint (scripts/lint.sh)"
  "unit tests (pytest)"
  "functional tests (root, loop devices)"
  "PSScriptAnalyzer"
  "fetch-assets.ps1 on powershell, exFAT VHDX"
  "fetch-assets.ps1 on pwsh, exFAT VHDX"
  "fetch-assets.ps1 on powershell, NTFS VHDX"
)
BUILD_CHECKS=(
  "build and boot-test the image (5.7)"
  "make-usb.sh --yes --profile ci on a loop device (2A.8)"
  "2B.8 offline provisioning, virtual NIC attached"
  "2B.16 offline provisioning, no NIC"
)

usage() { sed -n '2,/^# Test:/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }
die() {
  printf '%s: %s\n' "$prog" "$*" >&2
  exit 1
}
bad_usage() {
  printf '%s: %s Run with --help.\n' "$prog" "$*" >&2
  exit 2
}

while (($#)); do
  case "$1" in
    --repo)
      [[ $# -ge 2 && -n "$2" ]] || bad_usage "--repo needs OWNER/NAME."
      repo="$2"
      shift 2
      ;;
    --branch)
      [[ $# -ge 2 && -n "$2" ]] || bad_usage "--branch needs a name."
      branch="$2"
      shift 2
      ;;
    --reviews)
      [[ $# -ge 2 && "$2" =~ ^[0-6]$ ]] || bad_usage "--reviews needs a number from 0 to 6."
      reviews="$2"
      shift 2
      ;;
    --with-build) with_build=1; shift ;;
    --no-vuln-reporting) vuln_reporting=0; shift ;;
    --dry-run) dry_run=1; shift ;;
    --yes) yes=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) bad_usage "unknown option '$1'." ;;
  esac
done

if [[ -n "$repo" && ! "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  bad_usage "--repo must look like OWNER/NAME, not '$repo'."
fi
[[ "$branch" =~ ^[A-Za-z0-9._/-]+$ ]] || bad_usage "--branch '$branch' has characters a branch name cannot have."

command -v python3 >/dev/null 2>&1 || die "python3 is missing. Install it (apt install python3) and rerun."
if ((!dry_run)); then
  command -v gh >/dev/null 2>&1 || die "the GitHub CLI (gh) is missing. Install it, run 'gh auth login', and rerun."
fi
if [[ -z "$repo" ]]; then
  if ((dry_run)) && ! command -v gh >/dev/null 2>&1; then
    repo="OWNER/airlock"
  else
    repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null)" ||
      die "could not tell which GitHub repository this is. Pass --repo OWNER/NAME."
  fi
fi

checks=("${REQUIRED_CHECKS[@]}")
((with_build)) && checks+=("${BUILD_CHECKS[@]}")

# The JSON body is built by Python from argument values, so no value is ever parsed as code.
body="$(python3 - "$reviews" "${checks[@]}" <<'PY'
import json
import sys

reviews = int(sys.argv[1])
checks = sys.argv[2:]
body = {
    "required_status_checks": {"strict": True, "contexts": checks},
    "enforce_admins": True,
    "required_pull_request_reviews": {
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": False,
        "required_approving_review_count": reviews,
    },
    "restrictions": None,
    "required_linear_history": True,
    "allow_force_pushes": False,
    "allow_deletions": False,
    "required_conversation_resolution": True,
}
print(json.dumps(body, indent=2, sort_keys=True))
PY
)"

protect_path="repos/$repo/branches/$branch/protection"
vuln_path="repos/$repo/private-vulnerability-reporting"

if ((dry_run)); then
  printf 'would run: gh api --method PUT %s --input - (body below)\n' "$protect_path"
  printf '%s\n' "$body"
  ((vuln_reporting)) && printf 'would run: gh api --method PUT %s\n' "$vuln_path"
  exit 0
fi

if ((!yes)); then
  printf 'This changes the settings of %s:\n' "$repo"
  printf '  - branch %s: pull request required (%s approving review(s)), these checks green:\n' "$branch" "$reviews"
  printf '      %s\n' "${checks[@]}"
  printf '  - no force pushes, no deletion, linear history, rules apply to admins too\n'
  ((vuln_reporting)) && printf '  - private vulnerability reporting turned on\n'
  if [[ ! -t 0 ]]; then
    die "no terminal to ask on. Rerun with --yes to apply, or --dry-run to only print."
  fi
  read -r -p "Type yes to apply: " answer
  [[ "$answer" == "yes" ]] || die "nothing changed (you did not type yes)."
fi

printf '%s\n' "$body" | gh api --method PUT -H "Accept: application/vnd.github+json" "$protect_path" --input - >/dev/null ||
  die "GitHub refused the branch protection for $repo:$branch. Check that you have admin rights, that the branch exists, and that every workflow has run once; then rerun."
printf '%s: branch %s of %s is protected\n' "$prog" "$branch" "$repo"

if ((vuln_reporting)); then
  gh api --method PUT -H "Accept: application/vnd.github+json" "$vuln_path" >/dev/null ||
    die "could not turn on private vulnerability reporting for $repo. Turn it on by hand: Settings, Code security, Private vulnerability reporting."
  printf '%s: private vulnerability reporting is on\n' "$prog"
fi
