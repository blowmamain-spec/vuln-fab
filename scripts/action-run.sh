#!/usr/bin/env bash
# Runs vulnfab for the GitHub Action (and for local tests of the same logic).
# Inputs come from environment variables so that quoting is never an issue.
#   VULNFAB_PATH        directory to scan            (default ".")
#   VULNFAB_FAIL_ON     severity that fails the job   (default: never fail)
#   VULNFAB_MIN_CONF    confidence threshold          (default "medium")
#   VULNFAB_SINCE       git ref for diff mode         (default: full scan)
#   VULNFAB_SARIF       SARIF output file             (default "vulnfab.sarif")
#   VULNFAB_EXTRA_ARGS  extra arguments, split on spaces
# The step itself always exits 0 so that the SARIF upload can run; the exit code is exported as
# the step output "exit-code" and a later step fails the job with it.
set -uo pipefail

path="${VULNFAB_PATH:-.}"
sarif="${VULNFAB_SARIF:-vulnfab.sarif}"
args=(scan "$path" --format sarif --output "$sarif" --min-confidence "${VULNFAB_MIN_CONF:-medium}")
[ -n "${VULNFAB_FAIL_ON:-}" ] && args+=(--fail-on "$VULNFAB_FAIL_ON")
[ -n "${VULNFAB_SINCE:-}" ] && args+=(--since "$VULNFAB_SINCE")
if [ -n "${VULNFAB_EXTRA_ARGS:-}" ]; then
  # shellcheck disable=SC2206 - intentional word splitting of user-provided flags
  args+=(${VULNFAB_EXTRA_ARGS})
fi

vulnfab "${args[@]}"
code=$?

# exit codes: 0 clean, 1 findings at/above --fail-on, 2 usage error, 3 internal error
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "exit-code=$code"
    echo "sarif-file=$sarif"
  } >> "$GITHUB_OUTPUT"
fi
if [ "$code" -ge 2 ]; then
  echo "vulnfab failed with exit code $code" >&2
fi
exit 0
