# pstnhub-guardian

A Linux sidecar daemon that gates Squad game ports by beacon authentication.

It tails each Squad server log, allow-lists the source IP of every player that
completes the beacon (EOS) handshake, and — in enforce mode — default-drops the
game port for everyone else. One process gates every server on the box.

It runs **outside** the game server process, so it survives the server crashing
and keeps the firewall correct across restarts.

> **Alpha.** Running in production on one host. The nftables expression sequences
> and the log regexes are the parts most likely to need adjusting for your build —
> see [What is not proven](#what-is-not-proven).

---

## The short version

A crash exploit reaches Squad through an Unreal control channel using a peer that
**never authenticates**. Guardian makes the game port unreachable for anyone who
has not completed a real beacon handshake, so the exploit never gets to the code
it targets.

```
player -> beacon port (always open) -> completes EOS handshake
                                            |
                                            v
                              guardian sees it in the log
                                            |
                                            v
                          player IP added to the nftables allow-set
                                            |
                                            v
player -> game port ------------------------+--> allowed
attacker -> game port (never beaconed) --------> dropped in the kernel
```

Three properties worth understanding before you deploy it:

- **It never inspects packet contents.** The filter is "is this source IP on the
  allow-list", nothing more. An attacker mutating their packet bytes changes
  nothing.
- **It fails open, always.** Every exit path removes the drop rule. If the daemon
  dies, crashes, is killed, or the box OOMs, the game port reverts to accept-all.
  A broken guardian must never be a locked-out server.
- **The only way past it is to actually authenticate**, at which point the
  attacker is a named EOS/Steam identity you can permanently ban rather than a
  rotating VPN address.

---

## How it works, in detail

### What puts an IP on the allow-list

One log line, and only one:

```
LogNet: UNetConnection::Close: [UNetConnection] RemoteAddr: 1.2.3.4:43965,
   ... Def:BeaconNetDriver ... UniqueId: RedpointEOS:00022f92c00c4537b96cd84fbe3d4bae
```

A beacon-driver close carrying a **resolved EOS id**. The id is proof the
connection authenticated. Lines with `UniqueId: INVALID` are deliberately not
matched — that is precisely the attacker's signature.

The IP is added to an nftables set with a kernel-managed timeout (`allow_ttl`,
default 60m). The kernel expires entries, so there is no timer for the daemon to
get wrong.

`allow_ttl` is an **idle** timeout, not a session cap. Every accepted packet
refreshes the entry (`update @allowed { ip saddr timeout ... }` on the accept
rule), so a player in a twelve-hour session never ages out. Only someone who has
genuinely stopped sending traffic for that long expires — and they re-beacon on
their next join. Without that refresh the set entry would expire an hour after
the beacon regardless of activity, and everyone would be dropped mid-game, since
the handshake happens once at join and nothing would re-add them.

### What the firewall actually installs

Per server, one table containing one set and one chain:

```
table inet squad_main {
    set allowed { type ipv4_addr; flags timeout; }

    chain input {
        type filter hook input priority -10; policy accept;

        udp dport 15000 accept                      # beacon: never gated
        udp dport 27165 accept                      # query:  never gated
        # game: allowed players, and the match refreshes their idle timeout
        udp dport 7787 ip saddr @allowed update @allowed { ip saddr timeout 60m } accept
        udp dport 7787 limit rate 10/second log prefix "pstnhub-guardian drop: "
        udp dport 7787 counter drop                 # game:   everyone else
    }
}
```

The `log` rule is present only when `log_dropped_ips = true`.

Two details that are load-bearing:

- **The chain policy is `accept`, never `drop`.** The drop comes from an explicit
  rule that can be deleted. A policy that failed to reset would lock out every
  player.
- **The log rule is separate from the drop rule and carries no verdict.** A
  `limit` expression stops matching once the rate is exceeded; folding it into
  the drop rule would make the rule end early and the packet fall through to the
  accept policy — flooding fast enough would defeat the gate entirely. Keep them
  separate.

### Startup, and why it does not lock out a full server

Three mechanisms, in order:

1. **Persisted state.** Each server's allow-list is written to `state/<name>.json`
   every 30s and reloaded on boot. Covers crash → restart.
2. **Log backfill.** On start, the current live log is read from the beginning and
   its beacon lines replayed, so players already connected are recognised without
   having to re-authenticate. Runs concurrently with the live tail.
3. **The tailer opens at END** for live following, so normal operation never
   replays history.

Backfill ages each entry by the **log's own timestamps**, not the wall clock:
Squad writes local time with no timezone, so the last line in the file is treated
as "now" and everything else is placed relative to it. Only differences are used,
so the server's timezone cancels out. Entries already past `allow_ttl` are
dropped, and only beacon lines are replayed — replaying game-connection lines
would fire a would-drop alert per historical connection.

### Log rotation

Squad rotates on server start: the live log becomes
`SquadGame-backup-<timestamp>.log` and a fresh `SquadGame.log` appears. It also
writes `SquadGame-CRC.log` alongside.

`log_path` is a **pattern seed**, not a fixed file. Guardian follows the newest
live log matching `SquadGame.log` or `SquadGame_N.log`, and switches within 5s
when Squad starts a new one. Rotated and CRC logs are **never** followed: they
carry an mtime from the rotation instant, so a naive newest-file match latches
onto a dead file and replays hours of history, re-allowing players who left long
ago. A rotation means a server restart, which means every player disconnected, so
the previous log is genuinely irrelevant.

### What you see during an attack

In enforce mode the kernel drops silently — no Squad log line, so no event, so no
alert. Guardian recovers the two halves separately:

- **Volume**: a counter on the drop rule, polled every 30s. Rising counts are
  logged and pushed to Discord at most once per `notify_cooldown`.
- **Identity**: *optional*, off by default. With `log_dropped_ips = true` a
  rate-limited `log` rule puts source addresses in the kernel log, for
  cross-referencing with other hosts:

  ```bash
  sudo journalctl -k --since "1 hour ago" | grep 'pstnhub-guardian drop' | grep -oP 'SRC=\K[0-9.]+' | sort | uniq -c | sort -rn
  ```

  The rate cap (`log_drop_rate`, default 10/s) makes this a *sample*, not a
  census — good for identifying sources, useless for counting packets. Use the
  counter for volume.

  It is off by default because it is the only path where an attacker controls how
  much you write to disk. The cap bounds that, and the rule is deliberately
  separate from the drop rule so exceeding the rate stops the logging and never
  the dropping — but the safest volume is still none. Turn it on when you want
  addresses to share, off the rest of the time.

---

## Deploy guide

### 1. Build

```bash
cd /home/user/git/pstnhub-guardian
GOOS=linux GOARCH=amd64 go build -o pstnhub-guardian ./cmd/pstnhub-guardian
```

The unit and `run.sh` both expect the binary at the repo root under that name.

### 2. Create the service user (systemd only)

Skip this under screen: there you run as your own user, with the capability
granted directly to the binary by `setcap`.

```bash
sudo useradd --system --no-create-home pstnhub-guardian
sudo chown -R pstnhub-guardian /home/user/squad/PSTN/git/pstnhub-guardian
```

Either way the daemon needs `CAP_NET_ADMIN` to talk to nftables — from the unit
file or from `setcap`, never from running as root.

### 3. Configure

```bash
cp deploy/example.toml guardian.toml
cp deploy/example.env  .env
chmod 600 .env
```

Fill in the webhook in `guardian.env`, and the log paths and ports in
`guardian.toml`. **Confirm the ports against the running server first:**

```bash
ss -ulpn | grep SquadGame
```

Leave `enforce = false` for now. See the [config guide](#config-guide).

### 4. Run it under screen

The normal way to run this. Squad boxes already live in screen sessions, and the
guardian is one more window alongside them.

```bash
sudo setcap cap_net_admin+ep pstnhub-guardian
screen -dmS guardian deploy/run.sh
screen -r guardian      # watch it;  Ctrl-A D to detach
```

`run.sh` finds `guardian.toml`, `guardian.env` and the binary relative to its own
location, so a moved or renamed checkout still works. Its EXIT trap removes every
gating chain on Ctrl-C, on the binary crashing, or on the window being closed —
and it reads the table names out of your config, so it stays correct as you add
servers.

If you get `deploy/run.sh: Permission denied`, the executable bit did not survive
the checkout: `chmod +x deploy/run.sh`, or run it as `sh deploy/run.sh`.

`setcap` is wiped by every rebuild. Re-run it after each `go build`.

#### Surviving a reboot

Two lines in the service user's crontab (`crontab -e`):

```cron
@reboot sleep 30 && cd /home/user/squad/PSTN/git/pstnhub-guardian && screen -dmS guardian deploy/run.sh
```

The `sleep 30` lets the Squad servers come up first, so the log files exist and
backfill has something to read. If they take longer, raise it — a guardian that
starts early is not broken, it just starts with an empty allow-list and fills it
from the live log.

And the backstop that matters in enforce mode, in **root's** crontab:

```cron
@reboot /usr/sbin/nft delete chain inet squad_main input 2>/dev/null
```

One line per server table. This covers the one case `run.sh` cannot: SIGKILL, OOM,
or power loss, where the EXIT trap never runs and the drop rules survive into the
next boot with no daemon to maintain them. Without it, a hard kill in enforce mode
means players locked out until someone notices. In log-only mode none of this
applies — no chain is ever installed.

### 5. Validate in log-only mode

Run for **at least a week** and watch what it would have dropped:

```bash
screen -r guardian      # Ctrl-A D to detach again
```

Under systemd it goes to the journal instead:

```bash
journalctl -u pstnhub-guardian -f | grep 'WOULD DROP'
```

Every line should be the attacker or obvious garbage. If a real player appears —
the CGNAT or cached-direct-connect case, roughly 0.2% in our data — investigate
before enforcing. This week is the whole point: it is how you find out whether
your player base has anyone the beacon-first assumption does not hold for.

### 6. Enforce

Set `enforce = true` in `guardian.toml`, then restart:

```bash
screen -S guardian -X quit; screen -dmS guardian deploy/run.sh
```

Quitting the session first lets the trap remove the old chains cleanly. Under
systemd it is `sudo systemctl restart pstnhub-guardian`.

Before you do this, make sure the root crontab backstop from step 4 is in place —
from here on, a hard kill can leave drop rules behind.

Confirm the log says enforcing, the backfill found your players, and the chain is
really in the kernel:

```bash
screen -r guardian                            # "Enforce mode active", backfill count
sudo nft list ruleset | grep -A15 'table inet squad_main'
```

The backfill count should roughly match your current player count. If it is 0
with players online, roll back.

### Rollback

Opens the port immediately, no restart, no rebuild:

```bash
sudo nft delete chain inet squad_main input
```

Then set `enforce = false` and restart. One line per table if you run several
servers.

---

## Running under systemd instead

Optional. Worth it if you want the daemon supervised rather than trusted to stay
up in a screen window.

```bash
sudo cp deploy/pstnhub-guardian.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pstnhub-guardian
```

If your checkout is not at `/home/user/squad/PSTN/git/pstnhub-guardian`, edit the
paths in the unit first — systemd cannot derive them.

What it adds over screen:

- `CAP_NET_ADMIN` granted by the unit, so no `setcap` after every rebuild and no
  root.
- `WatchdogSec=30` + `Restart=always` catches a *wedged* daemon — one that is
  still running but no longer following the log. Nothing in the screen setup can
  notice that.
- `ExecStopPost` flushes the gating chains even on SIGKILL/OOM, replacing the
  root crontab backstop. **One line per server** — adding a `[[server]]` means
  adding its table there too.
- `ProtectSystem`, `RestrictAddressFamilies`, dedicated service user.

Do not run both. They would fight over the same nftables tables. Coming from
screen, quit that session first (`screen -S guardian -X quit`) so its trap removes
the chains cleanly.

---

## Config guide

Everything lives in `guardian.toml`, except the webhook, which is
`DISCORD_WEBHOOK_URL` in `guardian.env`. The webhook is never a flag — flags are
visible in `ps` to every user on the box.

### Global

| Key | Default | What it does |
|---|---|---|
| `enforce` | `false` | Master switch. `false` = log-only, nothing is ever dropped. This is the panic button: setting it false reverts every server at once. |
| `allow_ttl` | `"60m"` | **Idle** timeout for an allowed IP. Refreshed by every accepted packet, so it never cuts off an active player; only real inactivity ages an entry out. |
| `notify_cooldown` | `"5m"` | Per-source Discord aggregation window. |
| `heartbeat_interval` | `"10s"` | systemd watchdog ping. Keep well under `WatchdogSec` (30s). |
| `state_dir` | `"state"` | Where per-server allow-lists persist. |
| `log_level` | `"info"` | `debug`, `info`, `warn`, `error`. |
| `log_dropped_ips` | `false` | Write dropped packets' source addresses to the kernel log (`journalctl -k`). Off by default: attacker-controlled write volume. |
| `log_drop_rate` | `10` | Per-second cap on those lines. Makes the record a sample, not a census. |

### Per server

One `[[server]]` block each.

| Key | Required | What it does |
|---|---|---|
| `name` | yes | Identifies the server in logs, alerts, and its state filename. Unique, filesystem-safe. |
| `log_path` | yes | Pattern seed for the Squad log. `.../SquadGame.log` also follows `SquadGame_2.log`. |
| `game_port` | yes | The gated port. |
| `beacon_port` | — | Never gated. Gating it would break the only path onto the allow-list. |
| `query_port` | — | Never gated. |
| `nft_table` | — | Defaults to `squad_<name>`. Must be unique per server. |
| `nft_set` | — | Defaults to `allowed`. |
| `enforce` | — | Per-server opt-out. Omitted = follow the global switch. A server cannot opt *in* while the global switch is off. |

The loader refuses to start on a duplicate `name`, a duplicate `nft_table`, or a
duplicate `game_port`. All three fail silently at runtime — two servers sharing a
table fight over the same chain and one gates the other's port — so they are made
fatal at load instead.

### Adding a server

1. Add a `[[server]]` block to `guardian.toml`.
2. Add its table to the `ExecStopPost` lines in the unit file. **This is the one
   place the config is not the single source of truth**, and forgetting it means
   a drop rule that outlives the daemon.
3. `sudo systemctl restart pstnhub-guardian`.

To bring a new server up carefully while the others enforce, set `enforce = false`
in just its block.

---

## Log format

Guardian logs in the same shape as Squad's own log, so reading both during an
incident does not mean switching formats:

```
[30.08.2026-16:02:11.123] [Gate:main] Allowed player. [1.2.3.4 | 00022f92c00c4537b96cd84fbe3d4bae]
[30.08.2026-16:02:14.007] [Firewall:main WARN] Enforce mode active, game port is default-drop. [port=7787]
[30.08.2026-16:05:02.881] [Guardian] All servers running. [servers=2]
```

`[DD.MM.YYYY-HH:MM:SS.mmm] [Category:server] Message. [subject]`

The trailing bracket is the subject of the line — IP and EOS id when the event is
about a player, otherwise the relevant key/values. It is always last, so
addresses are greppable from any line:

```bash
journalctl -u pstnhub-guardian | grep -oP '\[\K[0-9.]+(?= \|)' | sort -u
```

Categories: `Guardian`, `Config`, `Server:<name>`, `Gate:<name>`,
`Firewall:<name>`, `Notify`, `Watchdog`. `WARN` and `ERROR` are appended to the
category; info is unmarked, as in Squad's log.

---

## Layout

```
cmd/pstnhub-guardian/   entry point, per-server supervision
internal/config/        TOML loading, defaults, collision checks
internal/logging/       Squad-style slog handler
internal/tailer/        log discovery, rotation, following, startup backfill
internal/parser/        the two regexes that matter
internal/gate/          decision layer + allow-list persistence
internal/firewall/      nftables over netlink
internal/notifier/      Discord webhook, aggregated
deploy/                 unit file, config templates, screen runner
```

---

## What is not proven

`go build`, `go vet`, and the test suite pass. What they cannot cover:

- **`internal/firewall`** — the `google/nftables` expression sequences (payload
  offsets, set lookup, UDP dport match, the limit/log rule ordering). Compiling
  proves the API calls exist, not that the rules are right. Confirm against
  `sudo nft -a list chain inet squad_main input` that the generated chain matches
  the layout above, and that the log rule sits *before* the drop rule.
- **`internal/parser`** — the two regexes are transcribed from sample logs and
  covered by a unit test, but that test only proves they match *those* lines.
  Re-confirm against a live log from **your** build; a plugin or engine bump can
  reword them.
- **Multi-server** — the config, collision checks, and per-server supervision are
  tested, but the alpha has only run against a single server in production.
- `firewall` and `gate` are Linux-only (netlink) and do not build on macOS or
  Windows. Build and test them with `GOOS=linux`.

Race detector needs cgo, so run it on the Linux host:

```bash
CGO_ENABLED=1 go test -race ./internal/...
```
