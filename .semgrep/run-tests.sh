#!/bin/sh
# Run every rule fixture in .semgrep/tests/ against .semgrep/trentina.yml.
#
# semgrep --test pairs a config FILE with targets of the same stem, so a
# single ruleset with one fixture per rule is tested one target at a time.
# Run from the repository root, with semgrep on PATH (CI uses the upstream
# image: docker.io/semgrep/semgrep).
set -eu
status=0
for target in .semgrep/tests/*.py; do
    echo "== $target"
    semgrep --test --config .semgrep/trentina.yml "$target" || status=1
done
exit "$status"
