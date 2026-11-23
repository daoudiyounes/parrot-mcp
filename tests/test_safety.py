"""Unit tests for the soft guardrails layer."""

import unittest

from parrot_mcp.safety import check_command


class TestDestructiveDetection(unittest.TestCase):
    def test_flags_rm_rf_system_paths(self):
        for cmd in [
            "rm -rf /",
            "rm -rf /*",
            "sudo rm -rf /",
            "rm -fr /",
            "rm -r -f /",
            "rm --recursive --force /",
            "rm -rf /etc",
            "rm -rf /etc/nginx",
            "rm -rf ~",
            "rm -rf $HOME",
            "rm -rf /usr /var",
        ]:
            with self.subTest(cmd=cmd):
                self.assertTrue(check_command(cmd), f"should flag: {cmd}")

    def test_flags_other_destructive(self):
        for cmd in [
            "dd if=/dev/zero of=/dev/sda",
            "dd if=junk of=/dev/nvme0n1",
            "mkfs.ext4 /dev/sdb1",
            "mkfs /dev/sdb",
            "shred /dev/sda",
            "cat junk > /dev/sda",
            "find / -delete",
            ":(){ :|:& };:",
            "chmod -R 000 /",
        ]:
            with self.subTest(cmd=cmd):
                self.assertTrue(check_command(cmd), f"should flag: {cmd}")

    def test_allows_everyday_and_pentest_commands(self):
        for cmd in [
            "rm -rf ./build",
            "rm -rf /tmp/loot",
            "rm notes.txt",
            "ls -la /",
            "cat /etc/os-release",
            "nmap -sS -p- 10.0.0.5",
            "sudo apt install nikto",
            "dd if=image.iso of=/tmp/disk.img",
            "chmod -R 755 /home/user/project",
            "grep -rf patterns /var/log/auth.log",
            "find /var/www -name '*.bak'",
            "sqlmap -u http://target/item.php?id=1 --batch",
        ]:
            with self.subTest(cmd=cmd):
                self.assertEqual(check_command(cmd), [], f"should allow: {cmd}")

    def test_disable_flag_clears_everything(self):
        self.assertEqual(check_command("rm -rf /", enabled=False), [])


if __name__ == "__main__":
    unittest.main()
