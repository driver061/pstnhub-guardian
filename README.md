# squad-gatekeeper

A Linux sidecar daemon that gates the Squad game port by beacon authentication.
It tails the Squad server log, allow-lists the source IP of every player that
completes the beacon (EOS) handshake, and — in enforce mode — default-drops the
game port for everyone else.

It runs **outside** the game server process, so it survives the server crashing
and keeps the firewall correct across restarts.

## Why this stops the crash exploit

The crash is a null virtual dispatch reached through an Unreal control channel by
a peer that **never authenticates** (no beacon handshake, `UniqueId: INVALID`).
Because that peer never completes the beacon, it never lands on the allow-list, so
in enforce mode its game-port packets are dropped before the server allocates the
connection object the exploit needs. The filter never inspects payloads, so it is
immune to the attacker mutating the packet bytes.

The only way past it is to complete a real beacon handshake first — i.e. actually
authenticate with a real account — at which point the attacker is a named
EOS/Steam identity you can permanently ban rather than a rotating VPN address.

## Status: builds and vets clean; not yet run against a live server

`GOOS=linux go build ./...` and `go vet` pass, and `go test ./internal/...` passes
for the parser and tailer. What is still unverified is everything that needs a real
kernel and a real log:

- **`internal/firewall`** — the `google/nftables` expression sequences (payload
  offsets, the set lookup, the UDP dport match). Compiling proves the API calls
  exist, not that the rules are right. Confirm against `nft list ruleset` that the
  generated rules match the chain layout in the package doc comment.
- **`internal/parser`** — the two regexes are transcribed from the sample logs and
  are covered by a unit test, but that test only proves they match *those* lines.
  Re-confirm against a live log from **your** build; a plugin/engine bump can
  reword them.
- The `firewall` and `gate` packages are Linux-only (netlink), so they do not build
  or test on macOS. Build them with `GOOS=linux`.

## Where things are configured

Everything per-server lives in one file in the checkout: `/home/user/squad/PSTN/git/pstnhub-guardian/<instance>.env`
(gitignored — it holds the webhook)
(template: `deploy/example.env`).

| What | Where |
|---|---|
| Discord webhook | `DISCORD_WEBHOOK_URL=` in that env file. Never a flag — flags show up in `ps`. Empty/absent = notifications off, everything else still works. |
| Ports | `GATEKEEPER_ARGS=... -game-port 7787 -beacon-port 15000 -query-port 27165` in that env file. |
| Log path | `-log` inside `GATEKEEPER_ARGS`. |
| Enforce | add `-enforce` to `GATEKEEPER_ARGS`. |
| nftables table | `NFT_TABLE=` in that env file. |

The port defaults (`7787` game, `15000` beacon, `27165` query) are **placeholders**.
Confirm what your server actually binds before enforcing:

```
ss -ulpn | grep SquadGameServer
```

## Multiple servers on one box

The unit is a systemd template, one instance per Squad server:

```
/home/user/squad/PSTN/git/pstnhub-guardian/main.env      ->  systemctl enable --now squad-gatekeeper@main
/home/user/squad/PSTN/git/pstnhub-guardian/server2.env   ->  systemctl enable --now squad-gatekeeper@server2
```

Each instance gets its own env file, its own state dir
(`/home/user/squad/PSTN/git/pstnhub-guardian/state/<instance>/allow.json`, created by `ExecStartPre`)
and its own log tail. Two things **must** differ between instances:

- `NFT_TABLE` — sharing a table means sharing a chain, and one instance's drop
  rule would gate the other's port. Name it after the instance (`squad_main`,
  `squad_server2`).
- `-game-port` — obviously.

`-beacon-port` and `-query-port` are only ever *accepted*, so overlap there is
harmless, but set them correctly per server anyway.

## Log rotation and `SquadGame_2.log`

Squad does not rotate its log predictably. Both `SquadGame.log` and
`SquadGame_2.log` can exist, and either one can be the live file depending on how
the server was last restarted. A daemon pinned to a single path goes silently deaf
in that case — exactly the failure that looks like "it just stopped working".

So `-log` is a **pattern seed, not a fixed target**. `/x/SquadGame.log` becomes the
pattern `/x/SquadGame*.log`, and the tailer:

- follows whichever match has the newest mtime, re-checked every 5s;
- switches when a sibling starts being written more recently than the current file
  (a *stale* sibling never wins, in either direction);
- reads the **first** file from the end (a restart must not replay old beacon lines
  and re-allow long-gone IPs) and every **later** file from the start (it appeared
  while we were running, so all of it is news);
- still handles ordinary in-place rotation/truncation of one path via `ReOpen`.

Covered by `internal/tailer/tailer_test.go`, including the flip case where
`SquadGame.log` is the newer of the two.

## Deploy runbook

1. Build into the checkout — the unit and `run.sh` both expect the binary at
   `/home/user/squad/PSTN/git/pstnhub-guardian/pstnhub-guardian`:
   ```
   cd /home/user/squad/PSTN/git/pstnhub-guardian
   GOOS=linux GOARCH=amd64 go build -o pstnhub-guardian ./cmd/gatekeeper
   ```
2. Create the user: `useradd --system --no-create-home squad-gatekeeper`, then give
   it the checkout: `chown -R squad-gatekeeper /home/user/squad/PSTN/git/pstnhub-guardian`.
3. Copy `deploy/squad-gatekeeper@.service` to `/etc/systemd/system/`. If your
   checkout is anywhere other than the path above, edit the four paths in it.
4. Per server, copy `deploy/example.env` to `/home/user/squad/PSTN/git/pstnhub-guardian/<instance>.env`,
   fill in the webhook, `NFT_TABLE`, ports and log path, then:
   ```
   chown squad-gatekeeper /home/user/squad/PSTN/git/pstnhub-guardian/<instance>.env
   chmod 0600 /home/user/squad/PSTN/git/pstnhub-guardian/<instance>.env
   ```
5. Confirm the ports (`ss -ulpn | grep SquadGameServer`).
6. `systemctl daemon-reload && systemctl enable --now squad-gatekeeper@<instance>`
7. **Run log-only for at least a week.** Watch the journal:
   ```
   journalctl -u squad-gatekeeper@<instance> -f | grep "WOULD DROP"
   ```
   Every would-drop line should be the attacker or obvious garbage. If a real
   player appears (the CGNAT / cached-direct-connect case — ~0.2% in our data),
   investigate before enforcing.
8. Once the would-drop list is clean across a restart or two, add `-enforce` to
   `GATEKEEPER_ARGS` in that instance's env file and
   `systemctl restart squad-gatekeeper@<instance>`.

## Running under screen (no systemd)

Easier to get going, and perfectly fine for the log-only validation week — log-only
never installs a chain, so there is nothing to fail open. `deploy/run.sh` reads the
**same** `/home/user/squad/PSTN/git/pstnhub-guardian/<instance>.env`, so the webhook and ports live in
one place either way.

```
sudo setcap cap_net_admin+ep /home/user/squad/PSTN/git/pstnhub-guardian/pstnhub-guardian   # or just run it with sudo
screen -dmS gatekeeper-main /home/user/squad/PSTN/git/pstnhub-guardian/deploy/run.sh main
screen -r gatekeeper-main      # watch it;  Ctrl-A D to detach
```

Multiple servers: one screen session per instance, same as one systemd instance per
server. `run.sh server2` reads `server2.env`.

```
screen -dmS gatekeeper-server2 /path/to/deploy/run.sh server2
```

**What you give up, and it only bites in enforce mode:** `run.sh` traps EXIT/INT/TERM
and removes the gating chain on the way out, which covers Ctrl-C, the binary
crashing, and closing the screen window. It cannot cover a SIGKILL of the process
group or the box losing power, and there is no watchdog restarting a wedged daemon.
Under systemd, `ExecStopPost` and `WatchdogSec` cover exactly those cases. So:
screen for the log-only week, systemd before you add `-enforce` — or if you insist
on screen while enforcing, put the backstop in root's crontab:

```
@reboot /usr/sbin/nft delete chain inet squad_main input
```

If it ever does get stuck, the manual unlock is one command:

```
sudo nft delete chain inet squad_main input
```

## Fail-open

If the daemon is not healthy, the drop rule must not be installed. Three layers:

- a deferred `firewall.Disable()` on every clean exit path and panic;
  (under screen, `deploy/run.sh`'s EXIT trap is the equivalent — see above for
  what it does and does not cover);
- `WatchdogSec=30` + `Restart=always` — a wedged daemon is killed and restarted;
- `ExecStopPost` runs `nft delete chain inet $NFT_TABLE input` even on SIGKILL/OOM,
  where Go defers cannot run.

The safe failure is the attacker getting back in, never your players locked out.
Test it: `systemctl kill -s SIGKILL squad-gatekeeper@<instance>` and confirm the game port is
open to all afterward (`nft list table inet $NFT_TABLE`).

## Layout

```
cmd/gatekeeper/main.go            wiring, signals, watchdog, fail-open defer
internal/config                   flags + env (webhook is env-only)
internal/tailer                   newest-log-wins follow: rotation + sibling switch
internal/parser                   log line -> typed event (the two regexes)
internal/firewall                 nftables over netlink: allow-set + gate rules
internal/gate                     decision layer + allow-list mirror + persistence
internal/notifier                 non-blocking Discord webhook w/ per-IP aggregation
deploy/squad-gatekeeper@.service  systemd template, one instance per server
deploy/example.env                per-instance config (webhook, ports, table)
deploy/run.sh                     screen launcher: same env file, trap-based fail-open
```

## What this is not

- Not a payload analyzer. It decides *whether the game port opens for an IP*, from
  the beacon event — it never inspects attack packets.
- Not a replacement for the vendor fix. The null-deref bug still exists in the EOS
  plugin; this makes it unreachable on your server. Report the bug so it's fixed
  for everyone (see the investigation handoff).
- Not IPv6-aware yet. The allow-set and `Allow()` handle IPv4 only; extend if your
  players connect over v6.
```
