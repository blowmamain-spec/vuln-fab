#!/usr/bin/env bash
# Clone benchmark targets at the SHAs pinned in targets.lock into benchmarks/targets/.
# Idempotent: existing checkouts at the right SHA are left alone. Usage: fetch_targets.sh [name...]
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p targets
want=("$@")
while read -r name url sha; do
  [[ -z "${name}" || "${name}" == \#* ]] && continue
  if [[ ${#want[@]} -gt 0 ]] && [[ ! " ${want[*]} " =~ " ${name} " ]]; then continue; fi
  dir="targets/${name}"
  if [[ -d "${dir}/.git" ]] && [[ "$(git -C "${dir}" rev-parse HEAD 2>/dev/null)" == "${sha}" ]]; then
    echo "ok      ${name} @ ${sha:0:10}"
    continue
  fi
  rm -rf "${dir}"
  git init -q "${dir}"
  git -C "${dir}" remote add origin "${url}"
  git -C "${dir}" fetch -q --depth 1 origin "${sha}"
  git -C "${dir}" -c advice.detachedHead=false checkout -q FETCH_HEAD
  echo "fetched ${name} @ ${sha:0:10}"
done < targets.lock
