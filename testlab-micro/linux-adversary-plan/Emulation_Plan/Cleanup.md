# Cleanup Guide

This guide removes files, processes, and sessions created while running
`Micro_Emulation_Plan.md` so `app-host` and `target-host` are ready for another
run. It is not intended to remove EDR/product telemetry — that lives in the
product's own console, not on the lab hosts.

Run sections in order. Steps 1–3 (and their alternates) leave live processes and
sockets behind — kill those before removing files, otherwise the files may be
re-locked or the process may respawn output you don't expect.

## Step 0 - Attacker-side payload artifacts

Run on `attacker`.

Kill the listener if it is still attached to a foreground terminal (`Ctrl+C`),
or find and kill it if it was backgrounded:

```bash
pkill -f "nc -lvnp 4444"
```

Optional — remove the local payload and its encoded copies once no longer needed
for another run:

```bash
rm -f backupv2 backupv2.hexstr backupv2.b64
```

## Step 1 / Step 1B - Reverse shell foothold

The reverse-shell process (`python3` in Step 1, `bash -i` in Step 1B) does not
write any file to `app-host` — cleanup here is process-only. If the shell was
left open (not `exit`ed) or the `nohup` wrapper is still alive after the shell
dropped, kill the leftover process tree under `svcapp`.

Run on `app-host`.

```bash
# Identify leftover reverse-shell processes spawned under the gunicorn worker
ps -ef --forest | grep -A3 gunicorn

# Kill by pattern - matches either the Step 1 python3 stdin payload or the
# Step 1B "bash -i ... /dev/tcp" invocation
pkill -u svcapp -f "python3$"
pkill -u svcapp -f "/dev/tcp/"
```

Verify no unexpected child remains under the `dummyapp` service:

```bash
ps -ef --forest | grep -A3 gunicorn
# Expected: only the gunicorn master + worker processes, no shell/python3 children
```

## Step 2 / Step 2B - Bindshell payload

Run on `app-host`.

Kill the running `backupv2` Meterpreter bind_tcp payload (same binary and port
for both Step 2 and Step 2B):

```bash
pkill -u svcapp -f "/tmp/backupv2"
```

Remove the written payload:

```bash
rm -f /tmp/backupv2
```

Verify:

```bash
ss -tlnp 2>/dev/null | grep 9001
# Expected: no output
ls -l /tmp/backupv2
# Expected: No such file or directory
```

On `attacker`, close the Meterpreter session opened against `app-host:9001` if
`msfconsole` is still attached:

```text
msf6 > sessions -K
```

## Step 3 - Port-forward tunnel

Run on `app-host`.

Kill the `pf.py` relay process:

```bash
pkill -u svcapp -f "/tmp/pf.py"
```

Remove the script:

```bash
rm -f /tmp/pf.py
```

Verify:

```bash
ss -tnp 2>/dev/null | grep -E ':2222|:22 '
# Expected: no :2222 listener remains
ls -l /tmp/pf.py
# Expected: No such file or directory
```

On `attacker`, close the SSH session opened through the forwarded port if still
open:

```bash
exit   # from the ssh -p 2222 session, if still attached
```

## Step 4 - Log and command-history clearing (irreversible)

Step 4 destroys evidence by design — `wtmp`, `btmp`, `auth.log`, and `lastlog`
are truncated in place, and `~/.bash_history` is shredded/removed. **None of
that content can be reconstructed by command.** If a fully clean audit trail is
required to analyze what the EDR/SIEM captured, restore `app-host` from a
pre-Step-4 VM/filesystem snapshot rather than trying to undo this step.

What *can* and *should* be reversed before the next run is the persistent
`/dev/null` symlink on `svcapp`'s history file — left in place, no commands run
by `svcapp` in a later run will ever be logged again, which will silently break
detection retesting for every subsequent step.

Run on `app-host` as `svcapp` (or root):

```bash
# Remove the symlink and restore a normal, writable history file
rm -f ~/.bash_history
touch ~/.bash_history
chmod 600 ~/.bash_history
unset HISTFILESIZE
```

Verify:

```bash
ls -la ~/.bash_history
# Expected: regular file, not "-> /dev/null"
```

If the optional `truncate -s 0`/selective-wtmp-record variants were run, no
extra artifacts remain — those commands either overwrite the same log files
already covered above or clean up their own temp files (`/tmp/.wtmp.txt`,
`/tmp/.wtmp.clean.txt`) inline. Confirm nothing was left behind:

```bash
ls -la /tmp/.wtmp*.txt 2>/dev/null
# Expected: No such file or directory
```

After restoring the history file, re-baseline per `Setup.md` §2.6 before the
next run — the old baseline files under `/root/baseline_*.txt` no longer reflect
current log state:

```bash
ps -ef --forest > /root/baseline_ps.txt
ss -tulnp > /root/baseline_ports.txt
last -f /var/log/wtmp | wc -l > /root/baseline_wtmp_entries.txt
lastb -f /var/log/btmp 2>/dev/null | wc -l > /root/baseline_btmp_entries.txt
lastlog | wc -l > /root/baseline_lastlog_entries.txt
stat -c '%n %s' /var/log/wtmp /var/run/utmp /var/log/btmp /var/log/auth.log /var/log/lastlog > /root/baseline_logfiles_size.txt
```

## Step 5 - SSH persistence via `authorized_keys`

Run on `app-host` as `svcapp` (or root).

Remove only the attacker's key line, not the whole file — `authorized_keys`
must exist but stay empty of attacker material for the next run per `Setup.md`
§2.3.

```bash
sed -i '/attacker@lab/d' ~svcapp/.ssh/authorized_keys
```

Verify:

```bash
cat ~svcapp/.ssh/authorized_keys
# Expected: empty (or unchanged pre-existing content, if any)
```

## Step 6 - Lateral movement to `target-host`

Step 6 only opens an SSH session using the seeded `opsuser` credential — it
does not write any file or leave a persistent process on `target-host`. No
artifact removal is required; the SSH session itself ends when the operator
exits it.

If the optional ancestry-contrast variant (SSH from the Step 5 key-based
session) was also run, no separate cleanup is needed beyond this section.

## Between-run reset (optional, keeps lab infra)

To return `app-host` to the exact pre-test state described in `Setup.md`
(e.g. before running the plan again against the same product, or before
demonstrating it to a new one), also confirm:

```bash
# No leftover attacker processes under svcapp
ps -ef --forest | grep svcapp

# No leftover listening ports besides dummyapp (8888) and sshd (22)
ss -tulnp
```

Do **not** remove the `dummyapp` systemd service, the `svcapp` account, or the
`/home/svcapp/app` virtualenv here — those are lab infrastructure from
`Setup.md` §2, reused across runs, not attack artifacts. Reverse them only in
the full decommission below.

## Full decommission — reverse `Setup.md` provisioning

Use this section only when the lab itself is being torn down (not between
runs). It reverses every provisioning step in `Setup.md` §2–§4. It does **not**
cover uninstalling the EDR/security product under test — that has its own
vendor-specific removal procedure, out of scope of this generic doc (`Setup.md`
§2.5).

### 1. Remove the app daemon (`Setup.md` §2.2)

Run on `app-host` as root.

```bash
systemctl disable --now dummyapp
rm -f /etc/systemd/system/dummyapp.service
systemctl daemon-reload

rm -rf /home/svcapp/app
```

Verify:

```bash
systemctl status dummyapp 2>&1 | head -3
# Expected: Unit dummyapp.service could not be found
curl -s "http://127.0.0.1:8888/" --max-time 2
# Expected: connection refused / timeout
```

### 2. Revoke log-write ACLs and group membership (`Setup.md` §2.1bis)

Run on `app-host` as root. Only needed if `svcapp` itself is being kept around
for some other purpose — if Step 3 below deletes the account, this is
redundant (the ACL entries and group membership are removed with the account)
but harmless to run first.

```bash
setfacl -x u:svcapp /var/log/btmp /var/log/auth.log /var/log/lastlog
gpasswd -d svcapp utmp
```

Verify:

```bash
getfacl /var/log/btmp /var/log/auth.log /var/log/lastlog | grep svcapp
# Expected: no output
id -nG svcapp
# Expected: no "utmp" in the list
```

### 3. Remove the `svcapp` service account (`Setup.md` §2.1)

Run on `app-host` as root. This also removes `/home/svcapp` (including
`.ssh/authorized_keys` from §2.3) since the account was created with `-m`.

```bash
userdel -r svcapp
```

Verify:

```bash
id svcapp
# Expected: no such user
ls -ld /home/svcapp
# Expected: No such file or directory
```

### 4. Remove baseline files (`Setup.md` §2.6)

Run on `app-host` as root.

```bash
rm -f /root/baseline_ps.txt /root/baseline_ports.txt /root/baseline_logsize.txt \
      /root/baseline_wtmp_entries.txt /root/baseline_btmp_entries.txt \
      /root/baseline_lastlog_entries.txt /root/baseline_logfiles_size.txt
```

### 5. Decommission `target-host` (`Setup.md` §3–§4)

Run on `target-host` as root. This removes the lateral-movement account and
whatever credential material was seeded for it in §4 (private key file,
password, or config/env-var placement chosen by the operator — remove it from
wherever it was actually placed, since §4 does not fix a specific location).

```bash
userdel -r opsuser
```

Verify:

```bash
id opsuser
# Expected: no such user
```

### 6. Optional — remove packages installed only for the lab

Only if these packages were not already present on `app-host`/`target-host`
for other purposes:

```bash
apt remove -y acl python3-venv
```

Leave `python3`, `python3-pip`, and `openssh-server` installed — removing them
risks breaking unrelated system tooling or remote access to the host.
