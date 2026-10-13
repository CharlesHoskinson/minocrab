#!/usr/bin/env bash
# Compile every .compact under corpus/src/ with the pinned compactc: the
# one on PATH when the flake devshell is active (`nix develop`, direnv —
# what CI's weekly job runs under), else `nix build .#compactc` at the
# repo root, which provides ../result/bin/compactc. $COMPACTC overrides.
# Keeps zkir/ + compiler/ outputs under corpus/zkir/, skips proving keys,
# discards the JS runtime output. Never stops on failure; results land in
# corpus/compile-report.tsv. Optional $1 limits to one source name.
set -uo pipefail
cd "$(dirname "$0")"

if [[ -z "${COMPACTC:-}" ]]; then
  COMPACTC="$(command -v compactc || true)"
  COMPACTC="${COMPACTC:-../result/bin/compactc}"
fi
if [[ ! -x "$COMPACTC" ]]; then
  echo "ERROR: compactc not found at $COMPACTC (enter the devshell, or run: nix build .#compactc)" >&2
  exit 1
fi
echo "compactc: $COMPACTC ($("$COMPACTC" --version 2>/dev/null | head -1))" >&2

FILTER="${1:-}"
REPORT="compile-report.tsv"
root="src${FILTER:+/$FILTER}"

# Cross-package imports (e.g. `import "@scope/pkg/..."`) resolve through
# COMPACT_PATH; sources.json's compact_path_links maps package names to
# corpus/src paths.
rm -rf .compact-path
mkdir -p .compact-path
jq -r '.compact_path_links // {} | to_entries[] | "\(.key)\t\(.value)"' sources.json |
while IFS=$'\t' read -r pkg target; do
  mkdir -p ".compact-path/$(dirname "$pkg")"
  # RELATIVE target, deliberately (notes/version-bump.org hazard 8 /
  # decision list item 6): an absolute one bakes in THIS checkout's path,
  # so the tracked symlink breaks in any other checkout (a worktree, a
  # clone) even though it still resolves here. `.compact-path/<pkg>` and
  # `src/<target>` are always siblings under `corpus/`, so the relative
  # path is one `../` per path component of `.compact-path/<pkg>` itself
  # (1 + the number of `/`s in `pkg`) followed by `src/<target>`.
  depth=$(($(grep -o "/" <<<"$pkg" | wc -l | tr -d ' ') + 1))
  prefix=""
  for ((i = 0; i < depth; i++)); do prefix="../$prefix"; done
  ln -sfn "${prefix}src/$target" ".compact-path/$pkg"
done
# RELATIVE too, for the same reason: compactc writes COMPACT_PATH-resolved
# sources into index.js.map (its `sourceRoot` / `sources`), and the
# contract-manifest.json we commit carries that file's hash — an absolute
# path here made every cross-package artifact depend on the checkout's
# location, so the weekly determinism job could not pass from CI's path.
export COMPACT_PATH=".compact-path"

# A source may carry its OWN links (a second pin of a repo whose packages
# import each other, e.g. signet-midnight-integration-pr127): those go into
# `.compact-path-<source>` and that source compiles with it on the path
# ahead of the shared one (M43 A).
declare -A SRC_PATH
while IFS=$'\t' read -r n pkg target; do
  dir=".compact-path-$n"
  mkdir -p "$dir/$(dirname "$pkg")"
  depth=$(($(grep -o "/" <<<"$pkg" | wc -l | tr -d ' ') + 1))
  prefix=""
  for ((i = 0; i < depth; i++)); do prefix="../$prefix"; done
  ln -sfn "${prefix}src/$target" "$dir/$pkg"
  SRC_PATH[$n]="$dir"
done < <(jq -r '.sources[] | select(.compact_path_links) | .name as $n | .compact_path_links | to_entries[] | [$n, .key, .value] | @tsv' sources.json)

# keep other sources' lines when filtering
if [[ -n "$FILTER" && -f "$REPORT" ]]; then
  grep -v "^src/$FILTER/" "$REPORT" > "$REPORT.tmp" || true
  mv "$REPORT.tmp" "$REPORT"
else
  : > "$REPORT"
fi

# Per-source extra compiler flags (e.g. --feature-zkir-v3), from sources.json.
declare -A SRC_FLAGS
while IFS=$'\t' read -r n fl; do
  SRC_FLAGS[$n]="$fl"
done < <(jq -r '.sources[] | select(.flags) | "\(.name)\t\(.flags | join(" "))"' sources.json)

total=0 ok=0
while IFS= read -r f; do
  total=$((total + 1))
  rel="${f%.compact}"
  out="zkir/${rel#src/}"
  srcname="${rel#src/}"; srcname="${srcname%%/*}"
  flags="${SRC_FLAGS[$srcname]:-}"
  rm -rf "$out"
  mkdir -p "$out"
  # shellcheck disable=SC2086 — flags are intentionally word-split
  path="${SRC_PATH[$srcname]:+${SRC_PATH[$srcname]}:}.compact-path"
  if err=$(COMPACT_PATH="$path" "$COMPACTC" --skip-zk $flags "$f" "$out" 2>&1); then
    ok=$((ok + 1))
    rm -rf "$out/contract" "$out/keys"
    printf '%s\tok\t\n' "$f" >> "$REPORT"
  else
    firstline=$(head -1 <<<"$err" | tr '\t' ' ')
    printf '%s\tfail\t%s\n' "$f" "$firstline" >> "$REPORT"
    rm -rf "$out"
  fi
done < <(find "$root" -name '*.compact' -type f 2>/dev/null | LC_ALL=C sort)

# LC_ALL=C, or the report's line ORDER depends on the caller's locale
# (en_US.UTF-8 ignores `.` and `_` when collating, C does not) and a
# recompile churns 26 unrelated lines. The report is a diff instrument for
# toolchain bumps — see notes/version-bump.org — so its order is pinned.
LC_ALL=C sort -o "$REPORT" "$REPORT"
echo "compiled $ok/$total OK (report: corpus/$REPORT)"
