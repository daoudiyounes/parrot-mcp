"""Unit tests for the structured tool command builders."""

import unittest

from parrot_mcp.tools.anon import build_macchanger_command
from parrot_mcp.tools.recon import (
    build_amass_command,
    build_dnsrecon_command,
    build_masscan_command,
    build_nmap_command,
)
from parrot_mcp.tools.vuln import (
    build_hashcat_command,
    build_hydra_command,
    build_sqlmap_command,
)
from parrot_mcp.tools.web import build_gobuster_command, build_nikto_command


class TestReconBuilders(unittest.TestCase):
    def test_nmap_default(self):
        self.assertEqual(build_nmap_command("10.0.0.5", None, "default", ""), "nmap -sV 10.0.0.5")

    def test_nmap_syn_with_ports_and_extra(self):
        cmd = build_nmap_command("10.0.0.5", "80,443", "syn", "--open")
        self.assertEqual(cmd, "nmap -sS -sV -p 80,443 --open 10.0.0.5")

    def test_nmap_unknown_type(self):
        with self.assertRaises(ValueError):
            build_nmap_command("t", None, "nonsense", "")

    def test_masscan(self):
        self.assertEqual(
            build_masscan_command("10.0.0.0/24", "80,443", 2000, ""),
            "masscan 10.0.0.0/24 -p80,443 --rate=2000",
        )

    def test_masscan_requires_ports(self):
        with self.assertRaises(ValueError):
            build_masscan_command("t", "", 1000, "")

    def test_amass(self):
        self.assertEqual(
            build_amass_command("example.com", True, ""),
            "amass enum -d example.com -passive",
        )
        self.assertEqual(build_amass_command("example.com", False, ""), "amass enum -d example.com")

    def test_dnsrecon(self):
        self.assertEqual(
            build_dnsrecon_command("example.com", "axfr", ""),
            "dnsrecon -d example.com -t axfr",
        )


class TestWebBuilders(unittest.TestCase):
    def test_gobuster_dir_default_wordlist(self):
        cmd = build_gobuster_command("dir", "http://10.0.0.5", None, "php,txt", "")
        self.assertEqual(
            cmd,
            "gobuster dir -u http://10.0.0.5 -w /usr/share/wordlists/dirb/common.txt -x php,txt",
        )

    def test_gobuster_dns(self):
        cmd = build_gobuster_command("dns", "example.com", None, None, "--no-error")
        self.assertIn("gobuster dns -d example.com -w", cmd)
        self.assertTrue(cmd.endswith("--no-error"))

    def test_gobuster_unknown_mode(self):
        with self.assertRaises(ValueError):
            build_gobuster_command("boom", "t", None, None, "")

    def test_nikto(self):
        self.assertEqual(
            build_nikto_command("10.0.0.5", 8443, True, ""),
            "nikto -h 10.0.0.5 -p 8443 -ssl",
        )


class TestVulnBuilders(unittest.TestCase):
    def test_hydra_defaults(self):
        cmd = build_hydra_command(
            "10.0.0.5",
            "ssh",
            None,
            "admin",
            None,
            None,
            "/usr/share/wordlists/rockyou.txt",
            "",
        )
        self.assertEqual(cmd, "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.5")

    def test_hydra_lists_and_port(self):
        cmd = build_hydra_command(
            "10.0.0.5", "ftp", 2121, None, "users.txt", None, "passes.txt", "-t 8"
        )
        self.assertEqual(cmd, "hydra -L users.txt -P passes.txt -s 2121 -t 8 ftp://10.0.0.5")

    def test_hydra_requires_creds(self):
        with self.assertRaises(ValueError):
            build_hydra_command("t", "ssh", None, None, None, None, None, "")

    def test_sqlmap_quotes_values(self):
        cmd = build_sqlmap_command(
            "http://t/a.php?id=1", "user=a&pass=b", 3, 2, "PHPSESSID=x y", True, "--dbs"
        )
        self.assertIn("--level=3", cmd)
        self.assertIn("--risk=2", cmd)
        self.assertIn("'user=a&pass=b'", cmd)
        self.assertIn("'PHPSESSID=x y'", cmd)
        self.assertIn("--forms", cmd)
        self.assertIn("--dbs", cmd)

    def test_hashcat_dict(self):
        cmd = build_hashcat_command("h.txt", 0, "/usr/share/wordlists/rockyou.txt", None, "")
        self.assertEqual(cmd, "hashcat -m 0 -a 0 h.txt /usr/share/wordlists/rockyou.txt")

    def test_hashcat_mask(self):
        cmd = build_hashcat_command("h.txt", 0, None, "?a?a?a?a?a?a", "")
        self.assertEqual(cmd, "hashcat -m 0 -a 3 h.txt '?a?a?a?a?a?a'")

    def test_shell_metacharacters_are_quoted(self):
        cmd = build_nmap_command("10.0.0.5; id", None, "default", "")
        self.assertEqual(cmd, "nmap -sV '10.0.0.5; id'")

    def test_ports_are_quoted(self):
        cmd = build_nmap_command("10.0.0.5", "80; id", "default", "")
        self.assertEqual(cmd, "nmap -sV -p '80; id' 10.0.0.5")
        cmd = build_masscan_command("10.0.0.5", "80; id", 1000, "")
        self.assertEqual(cmd, "masscan 10.0.0.5 -p'80; id' --rate=1000")

    def test_dnsrecon_scan_type_quoted(self):
        cmd = build_dnsrecon_command("example.com", "std; id", "")
        self.assertEqual(cmd, "dnsrecon -d example.com -t 'std; id'")

    def test_gobuster_extensions_quoted(self):
        cmd = build_gobuster_command("dir", "http://x", None, "php; id", "")
        self.assertIn("-x 'php; id'", cmd)

    def test_hashcat_requires_candidate(self):
        with self.assertRaises(ValueError):
            build_hashcat_command("h.txt", 0, None, None, "")


class TestAnonBuilders(unittest.TestCase):
    def test_macchanger_show(self):
        self.assertEqual(build_macchanger_command("eth0", "show", None), "macchanger -s eth0")

    def test_macchanger_random(self):
        cmd = build_macchanger_command("eth0", "random", None)
        self.assertIn("macchanger -r eth0", cmd)
        self.assertIn("ip link set dev eth0 down", cmd)
        self.assertIn("ip link set dev eth0 up", cmd)

    def test_macchanger_specific(self):
        cmd = build_macchanger_command("eth0", "specific", "02:11:22:33:44:55")
        self.assertIn("-m 02:11:22:33:44:55", cmd)

    def test_macchanger_specific_requires_mac(self):
        with self.assertRaises(ValueError):
            build_macchanger_command("eth0", "specific", None)


if __name__ == "__main__":
    unittest.main()
