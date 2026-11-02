import io
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sandbox_shell as sb  # noqa: E402


UNIT = """\
# /etc/systemd/system/demo.service
[Unit]
Description=Demo
After=network.target
RequiresMountsFor=/srv/data

[Service]
Type=notify
DynamicUser=yes
StateDirectory=%N
Environment="GREETING=hello world" \\
  # a comment inside a continuation is skipped
  MODE=test
; another comment
ExecStart=/usr/bin/demo --serve
Restart=on-failure
RuntimeMaxSec=1h
ProtectSystem=strict
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target

# /etc/systemd/system/demo.service.d/override.conf
[Service]
Environment=
Environment=MODE=override
CapabilityBoundingSet=
ReadWritePaths=/srv/data
"""


class ParseTest(unittest.TestCase):
    def test_entries_in_order_with_continuation(self):
        entries = sb.parse_unit_text(UNIT)
        self.assertIn(("Service", "Environment", '"GREETING=hello world" MODE=test'), entries)
        self.assertEqual(entries[0], ("Unit", "Description", "Demo"))
        self.assertEqual(entries[-1], ("Service", "ReadWritePaths", "/srv/data"))
        self.assertIn(("Install", "WantedBy", "multi-user.target"), entries)

    def test_fragment_path(self):
        self.assertEqual(sb.fragment_path_from_cat(UNIT), "/etc/systemd/system/demo.service")

    def test_garbage_line(self):
        with self.assertRaises(sb.Error):
            sb.parse_unit_text("[Service]\nthis is not an assignment\n")

    def test_trailing_continuation(self):
        self.assertEqual(sb.parse_unit_text("[Service]\nEnvironment=A=1 \\"),
                         [("Service", "Environment", "A=1")])


class SelectTest(unittest.TestCase):
    def setUp(self):
        self.props, self.dropped = sb.select_properties(sb.parse_unit_text(UNIT))

    def test_lifecycle_settings_dropped(self):
        keys = [k for k, _ in self.props]
        for k in ("Type", "ExecStart", "Restart", "RuntimeMaxSec"):
            self.assertNotIn(k, keys)
            self.assertIn(k, self.dropped)

    def test_unit_section_filtered(self):
        keys = [k for k, _ in self.props]
        self.assertIn("RequiresMountsFor", keys)
        self.assertNotIn("Description", keys)
        self.assertNotIn("After", keys)
        self.assertNotIn("WantedBy", keys)

    def test_empty_assignment_resets_and_is_kept(self):
        env = [v for k, v in self.props if k == "Environment"]
        self.assertEqual(env, ["", "MODE=override"])
        caps = [v for k, v in self.props if k == "CapabilityBoundingSet"]
        self.assertEqual(caps, [""])

    def test_user_mode_ignores_user_and_group(self):
        props, _ = sb.select_properties(
            sb.parse_unit_text("[Service]\nUser=nobody\nGroup=nogroup\nPrivateTmp=yes\n"), True)
        self.assertEqual(props, [("PrivateTmp", "yes")])

    def test_last_value(self):
        self.assertEqual(sb.last_value([("User", "a"), ("User", "b")], "User"), "b")
        self.assertIsNone(sb.last_value([("User", "a"), ("User", "")], "User"))


class ImplicitTest(unittest.TestCase):
    def test_dynamic_user_gets_unit_user_name(self):
        props = [("DynamicUser", "yes"), ("StateDirectory", "x")]
        notes = sb.add_implicit(props, "demo@inst.service")
        self.assertIn(("User", "demo"), props)
        self.assertTrue(notes)

    def test_explicit_user_kept(self):
        props = [("DynamicUser", "true"), ("User", "svc")]
        sb.add_implicit(props, "demo.service")
        self.assertEqual([v for k, v in props if k == "User"], ["svc"])

    def test_no_dynamic_user(self):
        props = [("DynamicUser", "no")]
        sb.add_implicit(props, "demo.service")
        self.assertEqual(props, [("DynamicUser", "no")])

    def test_runtime_directory_preserved(self):
        props = [("RuntimeDirectory", "demo")]
        sb.add_implicit(props, "demo.service")
        self.assertIn(("RuntimeDirectoryPreserve", "yes"), props)
        props = [("RuntimeDirectory", "demo"), ("RuntimeDirectoryPreserve", "restart")]
        sb.add_implicit(props, "demo.service")
        self.assertNotIn(("RuntimeDirectoryPreserve", "yes"), props)


class DynamicUserNameTest(unittest.TestCase):
    def test_siphash_reference_vectors(self):
        key = bytes(range(16))
        # From the SipHash paper / reference implementation (vectors.h).
        self.assertEqual(sb.siphash24(b"", key), 0x726FDB47DD0E0E31)
        self.assertEqual(sb.siphash24(bytes(range(15)), key), 0xA129CA6149BE45E5)
        self.assertEqual(sb.siphash24(bytes(range(8)), key), 0x93F5F5799A932462)

    def test_valid_prefix_used_as_is(self):
        self.assertEqual(sb.dynamic_user_name("demo.service"), "demo")
        self.assertEqual(sb.dynamic_user_name("demo@foo.service"), "demo")

    def test_invalid_prefix_hashed(self):
        name = sb.dynamic_user_name("org.example.demo.service")
        self.assertRegex(name, r"^_du[0-9a-f]{16}$")
        self.assertEqual(name, sb.dynamic_user_name("org.example.demo.service"))

    def test_valid_user_name(self):
        self.assertTrue(sb.valid_user_name("a-b_c1"))
        self.assertFalse(sb.valid_user_name("1abc"))
        self.assertFalse(sb.valid_user_name("a.b"))
        self.assertFalse(sb.valid_user_name("a" * 32))


class SpecifierTest(unittest.TestCase):
    def ctx(self, unit="web@foo-bar.service", user=False):
        return sb.SpecifierContext(unit, "/etc/systemd/system/web@.service", user,
                                   "web-foo-bar-sandbox-1.service")

    def test_names(self):
        c = self.ctx()
        self.assertEqual(c.expand("%n|%N|%p|%i|%I|%j|%f"),
                         "web@foo-bar.service|web@foo-bar|web|foo-bar|foo/bar|web|/foo/bar")
        self.assertEqual(c.expand("%y %Y"), "/etc/systemd/system/web@.service /etc/systemd/system")

    def test_escapes(self):
        c = self.ctx("dev-disk-by\\x2dlabel-data.service")
        self.assertEqual(c.expand("%P"), "dev/disk/by-label/data")
        self.assertEqual(c.expand("%j"), "data")

    def test_system_dirs(self):
        c = self.ctx()
        self.assertEqual(c.expand("%t %S %C %L %E %V %%"),
                         "/run /var/lib /var/cache /var/log /etc /var/tmp %")
        self.assertEqual(c.expand("%u %U %h"), "root 0 /root")
        self.assertEqual(c.expand("%d"), "/run/credentials/web-foo-bar-sandbox-1.service")

    def test_user_dirs(self):
        old = dict(os.environ)
        try:
            os.environ["XDG_RUNTIME_DIR"] = "/run/user/1234"
            os.environ["XDG_CONFIG_HOME"] = "/home/x/.config"
            c = self.ctx(user=True)
            self.assertEqual(c.expand("%t %E"), "/run/user/1234 /home/x/.config")
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_unknown_specifier(self):
        with self.assertRaises(sb.Error):
            self.ctx().expand("%Z")
        with self.assertRaises(sb.Error):
            self.ctx().expand("100%")


class CommandTest(unittest.TestCase):
    def test_systemd_run_command(self):
        cmd = sb.systemd_run_command([("User", "a"), ("Environment", '"A=b c"')],
                                     "x-sandbox-1.service", True, "pty", ["/bin/sh"], "desc")
        self.assertEqual(cmd, [
            "systemd-run", "--user", "--unit=x-sandbox-1.service", "--description=desc",
            "--collect", "--wait", "--quiet", "--pty",
            "-p", "User=a", "-p", 'Environment="A=b c"', "--", "/bin/sh"])

    def test_transient_name_sanitized(self):
        name = sb.transient_name("web@a b.service", "-preflight")
        self.assertRegex(name, r"^web-a_b-sandbox-\d+-preflight\.service$")

    def test_print_from_file(self):
        path = os.path.join(os.path.dirname(__file__), "fixtures", "demo.service")
        out = io.StringIO()
        with redirect_stdout(out):
            rc = sb.main(["--file", path, "--print", "--pipe", "-p", "Nice=5",
                          "--drop", "ProtectHome", "--", "id", "-u"])
        self.assertEqual(rc, 0)
        line = out.getvalue().strip()
        self.assertIn("--unit=demo-sandbox-", line)
        self.assertIn("-p StateDirectory=demo", line)
        self.assertIn("-p 'Environment=\"GREETING=hello world\" MODE=test'", line)
        self.assertIn("-p User=demo", line)
        self.assertIn("-p RuntimeDirectoryPreserve=yes", line)
        self.assertIn("-p Nice=5", line)
        self.assertNotIn("ProtectHome", line)
        self.assertNotIn("ExecStart", line)
        self.assertTrue(line.endswith("-- id -u"))

    def test_unit_and_file_conflict(self):
        self.assertEqual(sb.main(["x.service", "--file", "y.service", "--print"]), 1)

    def test_not_a_service(self):
        self.assertEqual(sb.main(["--file", "/dev/null", "--name", "x.socket", "--print"]), 1)


if __name__ == "__main__":
    unittest.main()
