#!/bin/sh
# Run the gatekeeper under screen instead of systemd.
#
#   screen -dmS gatekeeper-main deploy/run.sh main
#   screen -r gatekeeper-main          # look at it
#   Ctrl-A D                           # detach again
#
# Reads the SAME <repo>/<instance>.env as the systemd unit, so the webhook/ports/
# table live in one place whichever way you launch it. The repo root is derived
# from this script's own location, so a moved/renamed checkout still works.
# Override with GK_DIR=... or ENV_FILE=... for a local test.
#
# FAIL-OPEN, AND ITS LIMIT: the trap below removes the gating chain when this
# script exits — Ctrl-C, the binary crashing, the screen window being closed. It
# CANNOT run if the process group is SIGKILLed or the box loses power, and there
# is no watchdog here restarting a wedged daemon. In log-only mode none of that
# matters (no chain is ever installed). In ENFORCE mode it does: a hard kill
# leaves the drop rule in place and your players locked out until someone runs
#   nft delete chain inet <table> input
# If you enforce, use the systemd unit, or at least add that command to
# @reboot in root's crontab as a backstop.
set -eu

INSTANCE="${1:-main}"
# ponytail: repo root = this script's parent dir, no hardcoded install path.
GK_DIR="${GK_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
ENV_FILE="${ENV_FILE:-$GK_DIR/$INSTANCE.env}"
BIN="${BIN:-$GK_DIR/pstnhub-guardian}"
STATE_DIR="${STATE_DIR:-$GK_DIR/state/$INSTANCE}"

[ -r "$ENV_FILE" ] || { echo "no readable env file: $ENV_FILE" >&2; exit 2; }
. "$ENV_FILE"
: "${NFT_TABLE:?set NFT_TABLE in $ENV_FILE}"
: "${GATEKEEPER_ARGS:?set GATEKEEPER_ARGS in $ENV_FILE}"
export DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"

mkdir -p "$STATE_DIR"

# systemd's ExecStopPost, done by hand.
trap 'nft delete chain inet "$NFT_TABLE" input 2>/dev/null || true' EXIT INT TERM

# GATEKEEPER_ARGS is deliberately unquoted: it must word-split into flags.
# shellcheck disable=SC2086
"$BIN" -nft-table "$NFT_TABLE" -state "$STATE_DIR/allow.json" $GATEKEEPER_ARGS
