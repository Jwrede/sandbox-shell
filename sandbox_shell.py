#!/usr/bin/env python3
"""Run a shell or command inside the sandbox of a systemd service.

The service does not have to be running. sandbox-shell reads the unit file
and its drop-ins (``systemctl cat``), keeps the settings that describe the
execution environment (user, group, environment, working directory, mounts,
namespaces, capabilities, system call filters, resource limits, ...), drops
the settings that describe the service lifecycle (Exec*=, Type=, Restart=,
timeouts, standard input/output) and starts the requested command as a
transient unit with ``systemd-run``.
"""

import argparse
import os
import pwd
import grp
import re
import shlex
import shutil
import socket
import subprocess
import sys

__version__ = "0.1.0"

# [Service] settings that describe how the service is started, supervised
# and stopped, or where its standard streams go. They make no sense for an
# interactive command, and some of them (RuntimeMaxSec=, WatchdogSec=) would
# kill it.
DROP_KEYS = {
    "Type", "ExitType", "RemainAfterExit", "GuessMainPID", "PIDFile", "BusName",
    "ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload",
    "ExecStop", "ExecStopPost",
    "Restart", "RestartMode", "RestartSec", "RestartSteps", "RestartMaxDelaySec",
    "SuccessExitStatus", "RestartPreventExitStatus", "RestartForceExitStatus",
    "TimeoutSec", "TimeoutStartSec", "TimeoutStopSec", "TimeoutAbortSec",
    "TimeoutStartFailureMode", "TimeoutStopFailureMode",
    "RuntimeMaxSec", "RuntimeRandomizedExtraSec", "WatchdogSec", "WatchdogSignal",
    "RootDirectoryStartOnly", "PermissionsStartOnly", "NonBlocking", "NotifyAccess",
    "Sockets", "FileDescriptorStoreMax", "FileDescriptorStorePreserve",
    "USBFunctionDescriptors", "USBFunctionStrings", "OOMPolicy", "OpenFile",
    "ReloadSignal",
    "StandardInput", "StandardOutput", "StandardError", "StandardInputText",
    "StandardInputData", "TTYPath", "TTYReset", "TTYVHangup", "TTYVTDisallocate",
    "TTYRows", "TTYColumns",
}

# [Unit] settings that change the execution environment of the service.
UNIT_KEYS = {"JoinsNamespaceOf", "RequiresMountsFor"}

# systemd's EXIT_* codes (systemd.exec(5), "Process Exit Codes"): the
# process failed while systemd was setting up its execution environment.
EXIT_STATUS = {
    200: "CHDIR", 201: "NICE", 202: "FDS", 203: "EXEC", 204: "MEMORY",
    205: "LIMITS", 206: "OOM_ADJUST", 207: "SIGNAL_MASK", 208: "STDIN",
    209: "STDOUT", 210: "CHROOT", 211: "IOPRIO", 212: "TIMERSLACK",
    213: "SECUREBITS", 214: "SETSCHEDULER", 215: "CPUAFFINITY", 216: "GROUP",
    217: "USER", 218: "CAPABILITIES", 219: "CGROUP", 220: "SETSID",
    221: "CONFIRM", 222: "STDERR", 224: "PAM", 225: "NETWORK", 226: "NAMESPACE",
    227: "NO_NEW_PRIVILEGES", 228: "SECCOMP", 229: "SELINUX_CONTEXT",
    230: "PERSONALITY", 231: "APPARMOR_PROFILE", 232: "ADDRESS_FAMILIES",
    233: "RUNTIME_DIRECTORY", 235: "CHOWN", 236: "SMACK_PROCESS_LABEL",
    237: "KEYRING", 238: "STATE_DIRECTORY", 239: "CACHE_DIRECTORY",
    240: "LOGS_DIRECTORY", 241: "CONFIGURATION_DIRECTORY", 242: "NUMA_POLICY",
    243: "CREDENTIALS", 245: "BPF",
}

TRUE_WORDS = {"1", "yes", "y", "true", "t", "on"}

# Key used by systemd (src/core/unit.c, user_from_unit_name) to hash unit
# names that are not valid user names into a dynamic user name.
DYNAMIC_USER_HASH_KEY = bytes([
    0x58, 0x1a, 0xaf, 0xe6, 0x28, 0x58, 0x4e, 0x96,
    0xb4, 0x4e, 0xf5, 0x3b, 0x8c, 0x92, 0x07, 0xec,
])

MAX_RETRIES = 32


class Error(Exception):
    pass


# ---------------------------------------------------------------- parsing

def parse_unit_text(text):
    """Return (section, key, value) for every assignment, in file order.

    Follows systemd's syntax: '#' and ';' start comment lines, a trailing
    backslash continues the line (comment lines inside a continuation are
    skipped), whitespace around the key and the value is stripped.
    """
    logical = []
    pending = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(("#", ";")) or (not line and pending is None):
            continue
        if line.endswith("\\"):
            part = line[:-1].strip()
            pending = part if pending is None else pending + " " + part
            continue
        if pending is not None:
            line = (pending + " " + line).strip()
            pending = None
        logical.append(line)
    if pending:
        logical.append(pending)

    entries = []
    section = None
    for line in logical:
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if "=" not in line:
            raise Error("cannot parse unit file line: %r" % line)
        key, value = line.split("=", 1)
        entries.append((section, key.strip(), value.strip()))
    return entries


def fragment_path_from_cat(text):
    """The first '# /path' header of `systemctl cat` output."""
    for line in text.splitlines():
        if line.startswith("# /"):
            return line[2:].strip()
    return ""


# ------------------------------------------------------------- unit names

def split_unit_name(name):
    """Return (prefix, instance, suffix) of a unit name."""
    if "." not in name:
        raise Error("not a unit name: %r" % name)
    base, suffix = name.rsplit(".", 1)
    if "@" in base:
        prefix, instance = base.split("@", 1)
    else:
        prefix, instance = base, ""
    return prefix, instance, suffix


def unit_name_unescape(s):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "-":
            out.append("/")
        elif c == "\\" and i + 3 < len(s) and s[i + 1] == "x":
            out.append(chr(int(s[i + 2:i + 4], 16)))
            i += 3
        else:
            out.append(c)
        i += 1
    return "".join(out)


def unit_name_path_unescape(s):
    if s == "-" or s == "":
        return "/"
    p = unit_name_unescape(s)
    return p if p.startswith("/") else "/" + p


def transient_name(unit, tag):
    prefix, instance, _ = split_unit_name(unit)
    base = prefix + ("-" + instance if instance else "")
    base = re.sub(r"[^A-Za-z0-9:_.-]", "_", base)[:120]
    return "%s-sandbox-%d%s.service" % (base, os.getpid(), tag)


# ---------------------------------------------------------- dynamic users

def siphash24(data, key):
    """SipHash-2-4, as used by systemd (64-bit output)."""
    def rotl(x, b):
        return ((x << b) | (x >> (64 - b))) & 0xFFFFFFFFFFFFFFFF

    k0 = int.from_bytes(key[:8], "little")
    k1 = int.from_bytes(key[8:16], "little")
    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573
    mask = 0xFFFFFFFFFFFFFFFF

    def rounds(n):
        nonlocal v0, v1, v2, v3
        for _ in range(n):
            v0 = (v0 + v1) & mask; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32)
            v2 = (v2 + v3) & mask; v3 = rotl(v3, 16); v3 ^= v2
            v0 = (v0 + v3) & mask; v3 = rotl(v3, 21); v3 ^= v0
            v2 = (v2 + v1) & mask; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32)

    n = len(data)
    end = n - (n % 8)
    for i in range(0, end, 8):
        m = int.from_bytes(data[i:i + 8], "little")
        v3 ^= m
        rounds(2)
        v0 ^= m
    last = (n & 0xFF) << 56
    last |= int.from_bytes(data[end:].ljust(8, b"\0")[:7], "little")
    v3 ^= last
    rounds(2)
    v0 ^= last
    v2 ^= 0xFF
    rounds(4)
    return v0 ^ v1 ^ v2 ^ v3


def valid_user_name(name):
    """systemd's strict valid_user_group_name()."""
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,30}", name)) and not name.isdigit()


def dynamic_user_name(unit):
    """The user name systemd picks for DynamicUser=yes without User=."""
    prefix = split_unit_name(unit)[0]
    if valid_user_name(prefix):
        return prefix
    return "_du%016x" % siphash24(prefix.encode(), DYNAMIC_USER_HASH_KEY)


# ------------------------------------------------------------- specifiers

def _os_release():
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(path) as f:
                text = f.read()
        except OSError:
            continue
        out = {}
        for line in text.splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
        return out
    return {}


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


ARCHES = {"x86_64": "x86-64", "aarch64": "arm64", "i386": "x86", "i486": "x86",
          "i586": "x86", "i686": "x86", "armv7l": "arm", "armv6l": "arm",
          "ppc64le": "ppc64-le", "ppc64": "ppc64", "s390x": "s390x",
          "riscv64": "riscv64", "loongarch64": "loongarch64"}


class SpecifierContext:
    def __init__(self, unit, fragment, user_mode, transient):
        self.unit = unit
        self.fragment = fragment
        self.user_mode = user_mode
        self.transient = transient
        self._cache = {}

    def _manager_user(self):
        return pwd.getpwuid(os.geteuid() if self.user_mode else 0)

    def _dirs(self):
        if not self.user_mode:
            return {"t": "/run", "S": "/var/lib", "C": "/var/cache",
                    "L": "/var/log", "E": "/etc", "D": "/usr/share"}
        home = self._manager_user().pw_dir
        env = os.environ
        state = env.get("XDG_STATE_HOME") or os.path.join(home, ".local/state")
        return {
            "t": env.get("XDG_RUNTIME_DIR") or "/run/user/%d" % os.geteuid(),
            "S": env.get("XDG_STATE_HOME") or os.path.join(home, ".local/state"),
            "C": env.get("XDG_CACHE_HOME") or os.path.join(home, ".cache"),
            "L": os.path.join(state, "log"),
            "E": env.get("XDG_CONFIG_HOME") or os.path.join(home, ".config"),
            "D": env.get("XDG_DATA_HOME") or os.path.join(home, ".local/share"),
        }

    def value(self, c):
        if c in self._cache:
            return self._cache[c]
        prefix, instance, suffix = split_unit_name(self.unit)
        osr = None
        if c in "oOwWBMA":
            osr = _os_release()
        u = None
        if c in "uUgGhs":
            u = self._manager_user()
        if c == "n":
            v = self.unit
        elif c == "N":
            v = self.unit[: -(len(suffix) + 1)]
        elif c == "p":
            v = prefix
        elif c == "P":
            v = unit_name_unescape(prefix)
        elif c == "i":
            v = instance
        elif c == "I":
            v = unit_name_unescape(instance)
        elif c == "j":
            v = prefix.rsplit("-", 1)[-1]
        elif c == "J":
            v = unit_name_unescape(prefix.rsplit("-", 1)[-1])
        elif c == "f":
            v = unit_name_path_unescape(instance if instance else prefix)
        elif c in "tSCLED":
            v = self._dirs()[c]
        elif c == "T":
            v = os.environ.get("TMPDIR", "/tmp") if self.user_mode else "/tmp"
        elif c == "V":
            v = os.environ.get("TMPDIR", "/var/tmp") if self.user_mode else "/var/tmp"
        elif c == "u":
            v = u.pw_name
        elif c == "U":
            v = str(u.pw_uid)
        elif c == "g":
            v = grp.getgrgid(u.pw_gid).gr_name
        elif c == "G":
            v = str(u.pw_gid)
        elif c == "h":
            v = u.pw_dir
        elif c == "s":
            v = u.pw_shell or "/bin/sh"
        elif c == "H":
            v = socket.gethostname()
        elif c == "l":
            v = socket.gethostname().split(".", 1)[0]
        elif c == "q":
            v = socket.gethostname()
            for line in _read("/etc/machine-info").splitlines():
                if line.startswith("PRETTY_HOSTNAME="):
                    v = line.split("=", 1)[1].strip().strip('"')
        elif c == "m":
            v = _read("/etc/machine-id")
        elif c == "b":
            v = _read("/proc/sys/kernel/random/boot_id").replace("-", "")
        elif c == "v":
            v = os.uname().release
        elif c == "a":
            m = os.uname().machine
            v = ARCHES.get(m, m)
        elif c == "o":
            v = osr.get("ID", "")
        elif c == "w":
            v = osr.get("VERSION_ID", "")
        elif c == "W":
            v = osr.get("VARIANT_ID", "")
        elif c == "B":
            v = osr.get("BUILD_ID", "")
        elif c == "M":
            v = osr.get("IMAGE_ID", "")
        elif c == "A":
            v = osr.get("IMAGE_VERSION", "")
        elif c == "y":
            v = self.fragment
        elif c == "Y":
            v = os.path.dirname(self.fragment)
        elif c == "d":
            v = os.path.join(self._dirs()["t"], "credentials", self.transient)
        elif c == "%":
            v = "%"
        else:
            raise Error("unsupported specifier %%%s" % c)
        self._cache[c] = v
        return v

    def expand(self, text):
        out = []
        i = 0
        while i < len(text):
            c = text[i]
            if c == "%":
                if i + 1 >= len(text):
                    raise Error("lone %% at the end of %r" % text)
                out.append(self.value(text[i + 1]))
                i += 2
            else:
                out.append(c)
                i += 1
        return "".join(out)


# -------------------------------------------------------------- properties

def select_properties(entries, user_mode=False):
    """Pick the settings to carry over; return (properties, dropped keys).

    An empty assignment ("Key=") resets earlier assignments of that key, as in
    a unit file: the earlier ones are removed and the empty assignment is
    passed on, because for some settings it has a meaning of its own
    (CapabilityBoundingSet= is the empty set, not the default).
    """
    props = []
    dropped = []
    for section, key, value in entries:
        if section == "Service":
            if key in DROP_KEYS:
                if key not in dropped:
                    dropped.append(key)
                continue
        elif section == "Unit":
            if key not in UNIT_KEYS:
                continue
        else:
            continue
        if user_mode and key in ("User", "Group"):
            continue
        if value == "":
            props = [(k, v) for k, v in props if k != key]
        props.append((key, value))
    return props, dropped


def last_value(props, key):
    """The effective value of a setting; None if unset or reset to empty."""
    value = None
    for k, v in props:
        if k == key:
            value = v
    return value or None


def add_implicit(props, unit):
    """Settings that keep the transient unit from disturbing the service."""
    notes = []
    dyn = last_value(props, "DynamicUser")
    if dyn is not None and dyn.lower() in TRUE_WORDS and last_value(props, "User") is None:
        # Without User=, systemd derives the dynamic user from the unit name.
        # The transient unit has another name, so it would get another UID
        # and systemd would chown the service's StateDirectory= to it.
        name = dynamic_user_name(unit)
        props.append(("User", name))
        notes.append("User=%s (the dynamic user of %s)" % (name, unit))
    if last_value(props, "RuntimeDirectory") is not None and \
            last_value(props, "RuntimeDirectoryPreserve") is None:
        # Otherwise the directory is removed when the command exits, also
        # while the real service is running and using it.
        props.append(("RuntimeDirectoryPreserve", "yes"))
        notes.append("RuntimeDirectoryPreserve=yes")
    return notes


def systemd_run_command(props, name, user_mode, io_mode, command, description):
    cmd = ["systemd-run"]
    if user_mode:
        cmd.append("--user")
    cmd += ["--unit=" + name, "--description=" + description,
            "--collect", "--wait", "--quiet", "--" + io_mode]
    for key, value in props:
        cmd += ["-p", "%s=%s" % (key, value)]
    cmd.append("--")
    cmd += command
    return cmd


# ------------------------------------------------------------- the system

def run(cmd, **kw):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, **kw)


def load_unit(unit, user_mode):
    cmd = ["systemctl"] + (["--user"] if user_mode else []) + ["cat", "--no-pager", "--", unit]
    p = run(cmd)
    if p.returncode != 0:
        raise Error((p.stderr.strip() or "systemctl cat %s failed" % unit))
    return p.stdout


def load_files(paths):
    parts = []
    for path in paths:
        try:
            with open(path) as f:
                parts.append("# %s\n%s" % (os.path.abspath(path), f.read()))
        except OSError as e:
            raise Error("cannot read %s: %s" % (path, e.strerror))
    return "\n".join(parts)


UNKNOWN_RE = re.compile(r"(?:Unknown assignment: |Cannot set property |Unknown property )([A-Za-z0-9]+)")


def preflight(props, name, user_mode, true_cmd):
    """Start true_cmd with the properties; drop the ones systemd rejects.

    Returns (props, rejected keys, exit status, journal lines).
    """
    rejected = []
    for _ in range(MAX_RETRIES):
        cmd = systemd_run_command(props, name, user_mode, "pipe", true_cmd,
                                  "sandbox-shell preflight")
        p = run(cmd, stdin=subprocess.DEVNULL)
        if p.returncode == 0:
            return props, rejected, 0, []
        m = UNKNOWN_RE.search(p.stderr)
        if p.returncode == 1 and m and any(k == m.group(1) for k, _ in props):
            key = m.group(1)
            rejected.append(key)
            props = [(k, v) for k, v in props if k != key]
            continue
        if p.returncode in EXIT_STATUS:
            jcmd = ["journalctl"] + (["--user"] if user_mode else []) + \
                   ["-u", name, "-o", "cat", "--no-pager", "-q", "-n", "20"]
            j = run(jcmd)
            lines = [l for l in j.stdout.splitlines() if l.strip()]
            return props, rejected, p.returncode, lines
        raise Error("systemd-run failed (exit status %d):\n%s" % (p.returncode, p.stderr.strip()))
    raise Error("systemd-run kept rejecting settings: %s" % ", ".join(rejected))


def default_shell():
    for sh in ("/bin/bash", "/bin/sh"):
        if os.path.exists(sh):
            return sh
    return "/bin/sh"


# -------------------------------------------------------------------- CLI

def build_parser():
    p = argparse.ArgumentParser(
        prog="sandbox-shell",
        description="Run a shell or a command inside the sandbox of a systemd "
                    "service, using the settings of its unit file. The service "
                    "does not have to be running.",
        usage="%(prog)s [options] UNIT [-- COMMAND [ARG...]]\n"
              "       %(prog)s [options] --file PATH [--file PATH...] [-- COMMAND [ARG...]]",
        epilog="Without a command, an interactive shell is started. "
               "Example: sudo sandbox-shell nginx.service -- id")
    p.add_argument("unit", nargs="?", help="service unit, e.g. foo.service or foo@bar.service")
    p.add_argument("--user", action="store_true", help="use the user service manager")
    p.add_argument("--file", action="append", default=[], metavar="PATH",
                   help="read the unit from this file instead of systemctl cat "
                        "(repeat for drop-ins, in order)")
    p.add_argument("--name", help="unit name to assume with --file (default: the first file's name)")
    p.add_argument("-p", "--property", action="append", default=[], metavar="KEY=VALUE",
                   help="add or override a setting (applied after the unit's own)")
    p.add_argument("--drop", action="append", default=[], metavar="KEY",
                   help="do not carry over this setting")
    p.add_argument("--shell", help="shell to start (default: /bin/bash, else /bin/sh)")
    io = p.add_mutually_exclusive_group()
    io.add_argument("--pty", dest="io", action="store_const", const="pty",
                    help="allocate a terminal (default when stdin and stdout are terminals)")
    io.add_argument("--pipe", dest="io", action="store_const", const="pipe",
                    help="connect stdin/stdout/stderr directly")
    p.add_argument("--no-preflight", action="store_true",
                   help="skip the test start that detects rejected settings and sandbox failures")
    p.add_argument("--print", action="store_true", dest="print_only",
                   help="print the systemd-run command and exit")
    p.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    command = []
    if "--" in argv:
        i = argv.index("--")
        argv, command = argv[:i], argv[i + 1:]
    args = build_parser().parse_args(argv)
    try:
        return _main(args, command)
    except Error as e:
        print("sandbox-shell: %s" % e, file=sys.stderr)
        return 1


def _main(args, command):
    if args.file:
        if args.unit:
            raise Error("give either a unit name or --file (use --name to set the unit name)")
        unit = args.name or os.path.basename(args.file[0])
        text = load_files(args.file)
    else:
        if not args.unit:
            raise Error("name a service unit, or use --file")
        unit = args.unit if "." in args.unit else args.unit + ".service"
        text = load_unit(unit, args.user)
    if not unit.endswith(".service"):
        raise Error("%s is not a service unit" % unit)

    name = transient_name(unit, "")
    ctx = SpecifierContext(unit, fragment_path_from_cat(text), args.user, name)
    entries = parse_unit_text(text)
    props, dropped = select_properties(entries, args.user)
    drop = set(args.drop)
    props = [(k, v) for k, v in props if k not in drop]
    notes = add_implicit(props, unit)
    for item in args.property:
        if "=" not in item:
            raise Error("--property needs KEY=VALUE, got %r" % item)
        k, v = item.split("=", 1)
        props.append((k.strip(), v))
    props = [(k, ctx.expand(v)) for k, v in props]

    if not command:
        command = [args.shell or default_shell()]
    io_mode = args.io or ("pty" if sys.stdin.isatty() and sys.stdout.isatty() else "pipe")
    description = "sandbox-shell for %s" % unit

    if args.print_only:
        print(" ".join(shlex.quote(c) for c in
                       systemd_run_command(props, name, args.user, io_mode, command, description)))
        return 0

    if not shutil.which("systemd-run"):
        raise Error("systemd-run not found")

    rejected = []
    if not args.no_preflight:
        pre = transient_name(unit, "-preflight")
        props, rejected, status, journal = preflight(props, pre, args.user, ["/bin/true"])
        if status:
            print("sandbox-shell: the sandbox of %s cannot be set up: the test process "
                  "exited with status %d/%s before it ran." % (unit, status, EXIT_STATUS[status]),
                  file=sys.stderr)
            for line in journal:
                print("  " + line, file=sys.stderr)
            print("%s fails to start for the same reason. Use --drop KEY or "
                  "-p KEY=VALUE to try a fix, or --no-preflight to start anyway." % unit,
                  file=sys.stderr)
            return status

    if not args.quiet:
        user = last_value(props, "User") or ("current user" if args.user else "root")
        msg = "sandbox-shell: running %s as %s with %d settings of %s" % (
            " ".join(shlex.quote(c) for c in command), user, len(props), unit)
        print(msg, file=sys.stderr)
        if dropped:
            print("  not carried over: %s" % ", ".join(dropped), file=sys.stderr)
        if rejected:
            print("  rejected by systemd-run, left out: %s" % ", ".join(rejected), file=sys.stderr)
        for n in notes:
            print("  added: %s" % n, file=sys.stderr)
        sys.stderr.flush()

    cmd = systemd_run_command(props, name, args.user, io_mode, command, description)
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    sys.exit(main())
