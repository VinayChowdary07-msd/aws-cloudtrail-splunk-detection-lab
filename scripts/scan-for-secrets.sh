#!/usr/bin/env bash
# Pre-push check for the lab repo. Run from the repo root:  bash scripts/scan-for-secrets.sh
# Scans text files for AWS keys, account-ID-like numbers, canonical IDs, secret keys and real IPs.
# It cannot read images: open every file in screenshots/ and check it by eye before pushing.

set -u
cd "$(dirname "$0")/.." || exit 2
status=0

scan() {  # $1 = label, $2 = regex
  out=$(grep -RInE --exclude-dir=.git --exclude-dir=screenshots --exclude=scan-for-secrets.sh "$2" . 2>/dev/null)
  if [ -n "$out" ]; then
    echo "FOUND: $1"; echo "$out"; echo; status=1
  fi
}

scan "AWS access key ID (AKIA...)"        'AKIA[0-9A-Z]{16}'
scan "AWS temporary key ID (ASIA...)"     'ASIA[0-9A-Z]{16}'
scan "12-digit number (account ID?)"      '(^|[^0-9])[0-9]{12}([^0-9]|$)'
scan "64-char hex string (canonical ID?)" '[0-9a-f]{64}'
scan "possible AWS secret key"            '(aws_secret_access_key|secret[_ -]?access[_ -]?key)[^A-Za-z]{0,6}[A-Za-z0-9/+=]{40}'
scan "full IPv4 address"                  '(^|[^0-9.])([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9.]|$)'

if [ "$status" -eq 0 ]; then
  echo "Text scan clean. Now check each file in screenshots/ by eye (IP, account ID, key IDs, bucket names)."
else
  echo "Fix the items above before pushing."
fi
exit $status
