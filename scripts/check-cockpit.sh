#!/usr/bin/env bash
# Static check for the cockpit's JavaScript.
#
# `node --check` only parses. It cannot see a reference to a variable that
# does not exist, which is exactly the mistake an edit makes when it renames
# something and misses a use — and the cockpit has no build step and no
# tests, so that ships and is discovered by a person staring at an error.
#
# Biome's noUndeclaredVariables catches that class in about 30ms. It is not
# a type checker and is not trying to be; it is the cheapest thing that
# would have caught the bugs we actually shipped.
set -euo pipefail
cd "$(dirname "$0")/.."

BIOME="${BIOME:-$(command -v biome || true)}"
if [ -z "$BIOME" ]; then
  echo "check-cockpit: biome not found; set BIOME=/path/to/biome (skipping)" >&2
  exit 0
fi

FILES=(crates/apiary-hostd/src/cockpit.js crates/apiary-hostd/src/cockpit_api.js
       crates/apiary-hostd/src/cockpit_inference.js crates/apiary-hostd/src/signin.js)

for f in "${FILES[@]}"; do
  [ -f "$f" ] || continue
  cp "$f" "/tmp/$(basename "$f").mjs"
  node --check "/tmp/$(basename "$f").mjs"
done

"$BIOME" lint --config-path=.config/biome-cockpit.json "${FILES[@]}"
echo "cockpit: parses, and every identifier is declared"
