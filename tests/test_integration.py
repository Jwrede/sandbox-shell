"""Integration tests against the running system manager.

They install throwaway units under /run/systemd/system (names start with
"sbit"), so they need root and systemd as PID 1. Run them with:

    sudo SANDBOX_SHELL_INTEGRATION=1 python3 -m unittest tests.test_integration -v
"""
import glob
import os
import shutil
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = [sys.executable, os.path.join(HERE, "..", "sandbox_shell.py")]
UNIT_DIR = "/run/systemd/system"

ENABLED = os.environ.get("SANDBOX_SHELL_INTEGRATION") == "1" and os.geteuid() == 0 \
    and os.path.isdir("/run/systemd/system")


def sh(*cmd, check=True):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, check=check)


def tool(*args):
    return subprocess.run(TOOL + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          stdin=subprocess.DEVNULL, universal_newlines=True, timeout=60)


SERVICE = """\
[Service]
DynamicUser=yes
StateDirectory=%N
RuntimeDirectory=%N
WorkingDirectory=/var/lib/%N
Environment=MODE=base
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ExecStart={exec}
"""


@unittest.skipUnless(ENABLED, "needs root, systemd and SANDBOX_SHELL_INTEGRATION=1")
class IntegrationTest(unittest.TestCase):
    units = []

    @classmethod
    def install(cls, name, text, dropin=None):
        with open(os.path.join(UNIT_DIR, name), "w") as f:
            f.write(text)
        if dropin:
            d = os.path.join(UNIT_DIR, name + ".d")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "override.conf"), "w") as f:
                f.write(dropin)
        cls.units.append(name)

    @classmethod
    def setUpClass(cls):
        cls.install("sbit-run.service", SERVICE.format(exec="/bin/sleep 300"),
                    dropin="[Service]\nEnvironment=MODE=dropin\n")
        cls.install("sbit-fail.service", SERVICE.format(exec="/bin/false"))
        cls.install("sbit.dotted.service", SERVICE.format(exec="/bin/sleep 300"))
        cls.install("sbit-tpl@.service", "[Service]\nEnvironment=INST=%i\nExecStart=/bin/false\n")
        cls.install("sbit-bad.service",
                    "[Service]\nProtectSystem=strict\nReadWritePaths=/srv/sbit-missing\n"
                    "ExecStart=/bin/true\n")
        cls.install("sbit-unknown.service",
                    "[Service]\nNoSuchSetting=1\nPrivateTmp=yes\nExecStart=/bin/true\n")
        sh("systemctl", "daemon-reload")
        sh("systemctl", "start", "sbit-run.service", "sbit.dotted.service")
        sh("systemctl", "start", "sbit-fail.service", check=False)

    @classmethod
    def tearDownClass(cls):
        sh("systemctl", "stop", *cls.units, check=False)
        sh("systemctl", "reset-failed", *cls.units, check=False)
        for name in cls.units:
            for p in (os.path.join(UNIT_DIR, name), os.path.join(UNIT_DIR, name + ".d")):
                if os.path.isdir(p):
                    shutil.rmtree(p)
                elif os.path.exists(p):
                    os.remove(p)
        sh("systemctl", "daemon-reload")
        for p in glob.glob("/var/lib/private/sbit*") + glob.glob("/var/lib/sbit*"):
            if os.path.islink(p):
                os.remove(p)
            else:
                shutil.rmtree(p, ignore_errors=True)

    def main_pid_uid(self, unit):
        pid = sh("systemctl", "show", "-P", "MainPID", unit).stdout.strip()
        self.assertNotEqual(pid, "0")
        return os.stat("/proc/%s" % pid).st_uid

    def test_running_service_same_identity_and_sandbox(self):
        p = tool("-q", "sbit-run.service", "--", "sh", "-c",
                 'id -u; echo "$MODE"; pwd; touch /usr/sbit 2>/dev/null && echo usr-rw || echo usr-ro;'
                 ' touch state-file && echo state-rw; grep NoNewPrivs /proc/self/status')
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = p.stdout.split("\n")
        self.assertEqual(int(lines[0]), self.main_pid_uid("sbit-run.service"))
        self.assertEqual(lines[1], "dropin")
        self.assertEqual(lines[2], "/var/lib/private/sbit-run")
        self.assertEqual(lines[3], "usr-ro")
        self.assertEqual(lines[4], "state-rw")
        self.assertIn("1", lines[5])
        # The real service is untouched: still running, runtime directory kept.
        self.assertEqual(sh("systemctl", "is-active", "sbit-run.service").stdout.strip(), "active")
        self.assertTrue(os.path.exists("/run/sbit-run"))

    def test_failed_service(self):
        self.assertNotEqual(sh("systemctl", "is-active", "sbit-fail.service", check=False)
                            .stdout.strip(), "active")
        p = tool("-q", "sbit-fail", "--", "sh", "-c", "id -un; pwd")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.split(), ["sbit-fail", "/var/lib/private/sbit-fail"])

    def test_dynamic_user_of_unit_name_that_is_no_user_name(self):
        p = tool("-q", "sbit.dotted.service", "--", "id", "-u")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(int(p.stdout), self.main_pid_uid("sbit.dotted.service"))

    def test_template_instance_specifier(self):
        p = tool("-q", "sbit-tpl@foo.service", "--", "sh", "-c", 'echo "$INST"')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), "foo")

    def test_sandbox_failure_is_explained(self):
        p = tool("sbit-bad.service", "--", "true")
        self.assertEqual(p.returncode, 226)
        self.assertIn("226/NAMESPACE", p.stderr)
        self.assertIn("/srv/sbit-missing", p.stderr)

    def test_unknown_setting_left_out(self):
        p = tool("sbit-unknown.service", "--", "true")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("left out: NoSuchSetting", p.stderr)

    def test_exit_status_propagated(self):
        p = tool("-q", "sbit-fail.service", "--", "sh", "-c", "exit 7")
        self.assertEqual(p.returncode, 7)

    def test_file_mode(self):
        p = tool("-q", "--file", os.path.join(HERE, "fixtures", "demo.service"),
                 "--name", "sbit-file.service", "--", "sh", "-c", 'id -un; echo "$GREETING"')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.split("\n")[:2], ["sbit-file", "hello world"])


if __name__ == "__main__":
    unittest.main()
