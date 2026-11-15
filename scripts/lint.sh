#!/usr/bin/env bash
# Run every linter that is installed. CI runs this same script.
# Usage: scripts/lint.sh [all|shellcheck|yamllint|ansible-lint|ruff|packer|pwsh|pins]
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

which_check="${1:-all}"
failed=()
skipped=()

have() { command -v "$1" >/dev/null 2>&1; }

bash_files() {
  # Every tracked or untracked (not ignored) file whose first line is a bash shebang.
  git ls-files -co --exclude-standard -z \
    | while IFS= read -r -d '' f; do
        [[ -f "$f" ]] || continue
        if head -n1 -- "$f" 2>/dev/null | grep -Eq '^#!(/usr/bin/env bash|/bin/bash)'; then
          printf '%s\0' "$f"
        fi
      done
}

run_shellcheck() {
  if ! have shellcheck; then skipped+=(shellcheck); return 0; fi
  local files=()
  while IFS= read -r -d '' f; do files+=("$f"); done < <(bash_files)
  if ((${#files[@]} == 0)); then return 0; fi
  shellcheck -x -S style -- "${files[@]}" || failed+=(shellcheck)
}

run_yamllint() {
  if ! have yamllint; then skipped+=(yamllint); return 0; fi
  yamllint -s . || failed+=(yamllint)
}

run_ansible_lint() {
  if ! have ansible-lint; then skipped+=(ansible-lint); return 0; fi
  (cd ansible && ansible-lint --profile production site.yml roles) || failed+=(ansible-lint)
}

run_ruff() {
  if ! have ruff; then skipped+=(ruff); return 0; fi
  ruff check . || failed+=(ruff)
  ruff format --check . || failed+=(ruff-format)
}

run_packer() {
  if ! have packer; then skipped+=(packer); return 0; fi
  local tpl
  for tpl in packer/*.pkr.hcl; do
    [[ -e "$tpl" ]] || continue
    packer fmt -check -diff "$tpl" || failed+=("packer-fmt:$tpl")
  done
  if compgen -G 'packer/*.pkr.hcl' >/dev/null; then
    CHECKPOINT_DISABLE=1 packer validate -syntax-only packer/ || failed+=(packer-validate)
  fi
}

run_pwsh() {
  local files=()
  while IFS= read -r -d '' f; do files+=("$f"); done < <(git ls-files -co --exclude-standard -z -- '*.ps1' '*.psm1')
  if ((${#files[@]} == 0)); then return 0; fi
  if ! have pwsh; then skipped+=(psscriptanalyzer); return 0; fi
  if ! pwsh -NoProfile -Command 'if (Get-Module -ListAvailable PSScriptAnalyzer) { exit 0 } else { exit 3 }'; then
    skipped+=(psscriptanalyzer)
    # Still catch parse errors with the built-in parser.
    local f
    for f in "${files[@]}"; do
      # shellcheck disable=SC2016 # PowerShell variables, expanded by pwsh
      LINT_FILE="$f" pwsh -NoProfile -Command '$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:LINT_FILE,[ref]$null,[ref]$e); if ($e) { $e | ForEach-Object { Write-Output $_.ToString() }; exit 1 }' \
        || failed+=("pwsh-parse:$f")
    done
    return 0
  fi
  local f
  for f in "${files[@]}"; do
    # shellcheck disable=SC2016 # PowerShell variables, expanded by pwsh
    LINT_FILE="$f" pwsh -NoProfile -Command '$r = Invoke-ScriptAnalyzer -Path $env:LINT_FILE -Severity Warning,Error; if ($r) { $r | Format-Table -AutoSize | Out-String | Write-Output; exit 1 }' \
      || failed+=("psscriptanalyzer:$f")
  done
}

run_pins() {
  if [[ -f scripts/check-pins.py ]]; then
    python3 scripts/check-pins.py || failed+=(pins)
  fi
}

case "$which_check" in
  all)
    run_shellcheck; run_yamllint; run_ansible_lint; run_ruff; run_packer; run_pwsh; run_pins ;;
  shellcheck) run_shellcheck ;;
  yamllint) run_yamllint ;;
  ansible-lint) run_ansible_lint ;;
  ruff) run_ruff ;;
  packer) run_packer ;;
  pwsh) run_pwsh ;;
  pins) run_pins ;;
  *) echo "lint.sh: unknown check '$which_check'. Use all, shellcheck, yamllint, ansible-lint, ruff, packer, pwsh, or pins." >&2; exit 2 ;;
esac

if ((${#skipped[@]})); then
  echo "lint: skipped (tool not installed): ${skipped[*]}"
fi
if ((${#failed[@]})); then
  echo "lint: FAILED: ${failed[*]}" >&2
  exit 1
fi
echo "lint: ok"
