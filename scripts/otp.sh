#!/usr/bin/env bash
#
# Local-dev helper to see Gua verification codes (OTPs) while testing.
#
# In local/dev the SMS sender doesn't really text anything — it logs the code
# and stores it in Redis (key `otp:code:<E.164>`, TTL ~5 min). Production uses
# Twilio and never logs codes, so this is a dev convenience only.
#
# Usage:
#   scripts/otp.sh            # list every active code currently in Redis (phone = code)
#   scripts/otp.sh watch      # live-tail the identity-service log, highlighting codes
#   scripts/otp.sh <phone>    # print the code for one E.164 number, e.g. +5511999998888
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REDIS_CONTAINER="${GUA_REDIS_CONTAINER:-identity-redis}"
LOG_FILE="${GUA_IDENTITY_LOG:-$REPO_ROOT/logs/identity-service.log}"

redis() { docker exec "$REDIS_CONTAINER" redis-cli "$@"; }

list_all() {
  local keys
  keys="$(redis --scan --pattern 'otp:code:*' 2>/dev/null || true)"
  if [[ -z "$keys" ]]; then
    echo "No active codes in Redis. Trigger one from the app/web, then re-run."
    return 0
  fi
  printf '%-20s %s\n' "PHONE" "CODE"
  while IFS= read -r key; do
    [[ -z "$key" ]] && continue
    printf '%-20s %s\n' "${key#otp:code:}" "$(redis GET "$key" 2>/dev/null | tr -d '\r')"
  done <<< "$keys"
}

case "${1:-list}" in
  watch)
    echo "Watching $LOG_FILE for OTP codes (Ctrl-C to stop)…"
    # Works with the new 'GUA OTP' banner and the older 'verification code' line.
    tail -n0 -f "$LOG_FILE" | grep --line-buffered -iE 'GUA OTP|code  :|verification code is|Pretending to send SMS'
    ;;
  list|"")
    list_all
    ;;
  *)
    phone="$1"
    code="$(redis GET "otp:code:${phone}" 2>/dev/null | tr -d '\r' || true)"
    if [[ -n "$code" ]]; then
      echo "$phone -> $code"
    else
      echo "No active code for $phone. (Codes expire after ~5 min; check the number is E.164, e.g. +5511999998888.)"
    fi
    ;;
esac
