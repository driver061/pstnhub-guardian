#!/bin/sh
# Run the guardian under screen instead of systemd.
#
#   screen -dmS guardian deploy/run.sh
#   screen -r guardian                 # look at it
#   Ctrl-A D                           # detach again
#
# Reads the SAME guardian.toml and guardian.env as the systemd unit, so config
# lives in one place whichever way you launch it. The repo root is derived from
# this script's own location, so a moved or renamed checkout still works.
#
# FAIL-OPEN, AND ITS LIMIT: the trap below removes every gating chain when this
# script exits — Ctrl-C, the binary crashing, the screen window being closed. It
# CANNOT run if the process group is SIGKILLed or the box loses power, and there
# is no watchdog here restarting a wedged daemon. In log-only mode none of that
# matters (no chain is ever installed). In ENFORCE mode it does: a hard kill
# leaves the drop rules in place and your players locked out until someone runs
#   nft delete chain inet <table> input
# If you enforce, use the systemd unit.
set -eu

GK_DIR="${GK_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
CONFIG="${CONFIG:-$GK_DIR/guardian.toml}"
ENV_FILE="${ENV_FILE:-$GK_DIR/guardian.env}"
BIN="${BIN:-$GK_DIR/pstnhub-guardian}"

[ -r "$CONFIG" ] || { echo "no readable config: $CONFIG" >&2; exit 2; }
[ -x "$BIN" ] || { echo "no executable binary: $BIN (go build -o pstnhub-guardian ./cmd/pstnhub-guardian)" >&2; exit 2; }

# The webhook is optional: no env file just means no notifications.
if [ -r "$ENV_FILE" ]; then
    . "$ENV_FILE"
fi
export DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"

# systemd's ExecStopPost, done by hand. Pulls the table names out of the config
# so it stays correct when servers are added — the unit file cannot do this.
tables() {
    sed -n 's/^[[:space:]]*nft_table[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG"
    # Servers that omit nft_table get the derived default, squad_<name>.
    sed -n 's/^[[:space:]]*name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/squad_\1/p' "$CONFIG"
}
cleanup() {
    for t in $(tables); do
        nft delete chain inet "$t" input 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

# NOT exec: exec would replace this shell and the EXIT trap above would never
# run, silently losing the fail-open that is the whole point of the trap.
cd "$GK_DIR"
"$BIN" "$CONFIG"
