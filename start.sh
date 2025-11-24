#!/usr/bin/env bash
# start.sh — run the app in production
# set -e  # uncomment to stop on error

# if Node
if [ -f package.json ]; then
  # run build if necessary
  if [ -f package.json ] && jq -e '.scripts.build' package.json >/dev/null 2>&1; then
    npm run build || true
  fi
  npm run start || node index.js
  exit $?
fi

# if Python (gunicorn)
if [ -f requirements.txt ]; then
  exec gunicorn app:app --bind 0.0.0.0:"${PORT:-8000}"
fi

# fallback
echo "No start command found"
exit 1
