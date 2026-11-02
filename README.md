# sandbox-shell

Start a shell or a command inside the sandbox of a systemd service, with the
service's user, environment, working directory, mounts and restrictions. The
service does not have to be running, so this also works for a service that
fails at start and for the service of a timer.

```console
$ sudo sandbox-shell demo-app.service -- sh -c 'id; pwd; echo "$APP_ENV"; touch /srv/demo-app/uploads/x && echo uploads writable; touch /etc/x'
sandbox-shell: running sh -c 'id; pwd; echo "$APP_ENV"; touch /srv/demo-app/uploads/x && echo uploads writable; touch /etc/x' as demo-app with 7 settings of demo-app.service
  not carried over: ExecStart
  added: User=demo-app (the dynamic user of demo-app.service)
uid=61953(demo-app) gid=61953(demo-app) groups=61953(demo-app)
/var/lib/private/demo-app
production
touch: cannot touch '/srv/demo-app/uploads/x': Permission denied
touch: cannot touch '/etc/x': Read-only file system
```

Here `demo-app.service` has `DynamicUser=yes`, `ProtectSystem=strict` and
`ReadWritePaths=/srv/demo-app/uploads` and is not running (its last start
failed, see the preflight example below). The command runs as the service's
dynamic user and shows that the uploads directory, created by root, is not
writable for that user.

Without a command it starts an interactive shell (`/bin/bash`, else
`/bin/sh`).

## Why

Debugging a sandboxed service usually means reproducing its sandbox by hand:
`systemd-run -p User=... -p ProtectSystem=... -p ReadWritePaths=...`, one
property per line of the unit file and its drop-ins, or entering the
namespaces of the running process with `nsenter`. Neither works well when the
service is not running, uses `DynamicUser=`, or has twenty such settings.

- [systemd/systemd#28163](https://github.com/systemd/systemd/issues/28163)
  "Get a shell in the environment/sandbox of an existing service" (37 thumbs-up reactions,
  open since June 2023). The answers in the thread were `nsenter` and
  `systemd-run --property`. systemd 258 added `systemd-analyze unit-shell`,
  which enters a *running* unit. The latest comments (January and February
  2026) ask for the same thing for a unit that crashed at start, as its
  dynamic user rather than root. The suggested workaround was to edit the unit
  to run `sleep infinity`.
- [systemd/systemd#9907](https://github.com/systemd/systemd/issues/9907)
  "Allow passing a .service file to systemd-run" (20 thumbs-up reactions, open since August
  2018), to test a daemon "with the same sandboxing options used in the
  installed/deployed version".
- [systemd/systemd#42641](https://github.com/systemd/systemd/issues/42641):
  `systemd-analyze --user unit-shell` requires permissions that an
  unprivileged user cannot acquire.

I found no tool that builds the `systemd-run` call from a unit file.

## How it works

1. Reads the unit and its drop-ins with `systemctl cat` (or the files given
   with `--file`) and parses them like systemd does: comments, line
   continuations, and an empty assignment (`Key=`) resetting earlier ones.
2. Keeps the `[Service]` settings that describe the execution environment
   and `JoinsNamespaceOf=` and `RequiresMountsFor=` from `[Unit]`. It drops
   the settings that describe the service lifecycle and its standard streams:
   `Exec*=`, `Type=`, `Restart*=`, timeouts, `RuntimeMaxSec=`, `WatchdogSec=`,
   `Sockets=`, `StandardInput/Output/Error=`, `TTY*=` and a few more. It
   prints which ones it dropped.
3. Expands unit specifiers (`%n`, `%N`, `%i`, `%I`, `%p`, `%t`, `%S`, `%h`,
   ...) with the values of the original unit, so `StateDirectory=%N` names the
   service's directory and not the transient unit's.
4. Adds two settings so the transient unit does not disturb the real service:
   - `DynamicUser=yes` without `User=`: systemd derives the user name from the
     unit name (the prefix, or `_du` and a SipHash of it if the prefix is not a
     valid user name). sandbox-shell sets `User=` to that name. Units with the
     same dynamic user name share the UID, so the command runs with the
     service's UID, and systemd does not chown the service's `StateDirectory=`
     to a new UID.
   - `RuntimeDirectory=` without `RuntimeDirectoryPreserve=`: adds
     `RuntimeDirectoryPreserve=yes`, so the directory is not removed when the
     command exits while the service still uses it.
5. Preflight: starts `/bin/true` once with the same settings. Settings that
   `systemd-run` rejects for transient units are left out and reported. If
   systemd cannot set up the sandbox at all, it prints the exit status and the
   journal lines that explain it, and exits with that status:

   ```console
   $ sudo sandbox-shell demo-app.service
   sandbox-shell: the sandbox of demo-app.service cannot be set up: the test process exited with status 226/NAMESPACE before it ran.
     Started demo-app-sandbox-574315-preflight.service - sandbox-shell preflight.
     demo-app-sandbox-574315-preflight.service: Failed to set up mount namespacing: /srv/demo-app/uploads: No such file or directory
     demo-app-sandbox-574315-preflight.service: Main process exited, code=exited, status=226/NAMESPACE
     demo-app-sandbox-574315-preflight.service: Failed with result 'exit-code'.
   demo-app.service fails to start for the same reason. Use --drop KEY or -p KEY=VALUE to try a fix, or --no-preflight to start anyway.
   ```

6. Runs `systemd-run --wait --collect --pty` (or `--pipe` when stdin or
   stdout is not a terminal) with the settings and the command, and exits with
   the command's exit status.

## Installation

Python 3.8 or newer, no dependencies.

```sh
pipx install git+https://github.com/Jwrede/sandbox-shell
# or copy the single file
curl -o /usr/local/bin/sandbox-shell https://raw.githubusercontent.com/Jwrede/sandbox-shell/main/sandbox_shell.py
chmod +x /usr/local/bin/sandbox-shell
```

With pipx, `sudo` may not find the command; use `sudo $(command -v sandbox-shell)`.

## Usage

```text
sandbox-shell [options] UNIT [-- COMMAND [ARG...]]
sandbox-shell [options] --file PATH [--file PATH...] [-- COMMAND [ARG...]]

  --user             use the user service manager
  --file PATH        read the unit from this file instead of systemctl cat
                     (repeat for drop-ins, in order)
  --name NAME        unit name to assume with --file (default: the first file's name)
  -p KEY=VALUE       add or override a setting (applied after the unit's own)
  --drop KEY         do not carry over this setting
  --shell PATH       shell to start
  --pty / --pipe     force a terminal, or plain stdin/stdout/stderr
  --no-preflight     skip the test start
  --print            print the systemd-run command and exit
  -q, --quiet        no summary on stderr
```

Examples:

```sh
# a shell as the service's (dynamic) user, in its working directory
sudo sandbox-shell myapp.service

# does the sandbox allow writing there?
sudo sandbox-shell myapp.service -- touch /var/lib/myapp/test

# try a change before editing the unit
sudo sandbox-shell myapp.service -p ReadWritePaths=/srv/myapp -- ls -l /srv/myapp

# test a unit file before installing it
sudo sandbox-shell --file ./myapp.service -- /usr/bin/myapp --check-config

# user units, no root needed
sandbox-shell --user syncthing.service

# see what would be run
sandbox-shell --print myapp.service
```

System units need root (or polkit authorization), like `systemd-run`.

## Tests

- `tests/test_unit.py`: 27 tests for the parser (continuations, comments,
  drop-ins, empty assignments), the selection of settings, the dynamic user
  name (SipHash-2-4 against the reference vectors), specifiers and the
  generated command.
- `tests/test_integration.py`: 8 tests against the real system manager.
  They install throwaway units under `/run/systemd/system` and check that the
  command runs with the UID of the running service's main process (also for a
  unit name that is not a valid user name, which exercises the SipHash
  derivation), sees the drop-in's environment, has a read-only `/usr` and a
  writable state directory, that the running service and its runtime
  directory survive, that a failed service works too, that `%i` of a template
  instance is expanded, that a sandbox failure is reported with status 226 and
  the missing path, that an unknown setting is left out, and that the exit
  status is passed through.

```sh
python3 -m unittest tests.test_unit -v
sudo SANDBOX_SHELL_INTEGRATION=1 python3 -m unittest tests.test_integration -v
```

CI runs the unit tests on Python 3.8, 3.11 and 3.13 and the integration tests
on the GitHub runners for Ubuntu 24.04 (systemd 255) and Ubuntu 22.04
(systemd 249). The interactive `--pty` path was tested by hand.

## Limitations

- It starts a new transient unit. It does not enter the namespaces of a
  running service: with `PrivateTmp=yes` or `PrivateNetwork=yes` the command
  gets its own `/tmp` or network namespace, not the service's. For that, use
  `systemd-analyze unit-shell` (systemd 258 or newer) or `nsenter`.
- Settings are passed in unit-file syntax to `systemd-run -p`. Settings that
  cannot be set on transient units are left out, and the preflight reports
  them. Specifiers that the tool does not know are an error.
- `LoadCredential=` and similar settings load credentials into the transient
  unit's own credentials directory; `%d` points there.
- Socket activation and the `ExecStartPre=` and `ExecStartPost=` steps are
  not reproduced; only the sandbox is.
- The preflight starts `/bin/true` once with the service's settings, which
  creates its `StateDirectory=` and similar directories like a real start
  would. Use `--no-preflight` to avoid it.
- Only tested with systemd 255 locally and 255 and 249 in CI.

## License

MIT
