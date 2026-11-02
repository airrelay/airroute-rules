#!/usr/bin/env bash
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_root/web/console"
npm ci --no-audit --no-fund
npm run build
cd "$project_root"
cargo build --release --locked --bins
printf 'Built: %s\n' "$project_root/target/release/rules-control" "$project_root/target/release/rules-probe"
