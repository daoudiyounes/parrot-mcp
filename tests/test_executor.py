"""Unit tests for executor helpers and local execution."""

import json
import os
import pathlib
import shutil
import tempfile
import unittest
from unittest.mock import patch

from parrot_mcp.config import Config
from parrot_mcp.executor import CommandResult, Executor, _clip
from parrot_mcp.state import EXECUTOR


class TestClip(unittest.TestCase):
    def test_short_text_untouched(self):
        self.assertEqual(_clip("hello", 100), "hello")

    def test_long_text_keeps_head_and_tail(self):
        text = "A" * 5000 + "MIDDLE" + "B" * 5000
        clipped = _clip(text, 2000)
        self.assertLess(len(clipped), len(text))
        self.assertTrue(clipped.startswith("AAAA"))
        self.assertTrue(clipped.endswith("BBBB"))
        self.assertIn("output clipped", clipped)


class TestRender(unittest.TestCase):
    def test_render_contains_key_fields(self):
        result = CommandResult(
            command="ls /",
            exit_code=0,
            stdout="etc\nhome",
            stderr="",
            duration_sec=0.5,
            target="local",
        )
        rendered = result.render()
        self.assertIn("$ ls /", rendered)
        self.assertIn("[target=local]", rendered)
        self.assertIn("exit=0", rendered)
        self.assertIn("etc", rendered)

    def test_missing_binary_hint(self):
        result = CommandResult(
            command="hydra -l admin -P pw.txt ssh://10.0.0.5",
            exit_code=127,
            stdout="",
            stderr="/bin/sh: 1: hydra: not found",
            duration_sec=0.1,
            target="docker",
        )
        rendered = result.render()
        self.assertIn("apt install hydra", rendered)

    def test_missing_binary_hint_from_wrapper_script(self):
        result = CommandResult(
            command="command -v hydra >/dev/null 2>&1 || { echo 'not installed: hydra'; exit 127; };",
            exit_code=127,
            stdout="not installed: hydra\n",
            stderr="",
            duration_sec=0.1,
            target="docker",
        )
        rendered = result.render()
        self.assertIn("apt install hydra", rendered)
        self.assertNotIn("apt install command", rendered)

    def test_missing_binary_hint_ignores_unknown_message(self):
        result = CommandResult(
            command="something",
            exit_code=127,
            stdout="",
            stderr="weird failure",
            duration_sec=0.1,
            target="docker",
        )
        self.assertNotIn("apt install", result.render())

    def test_missing_binary_hint_uses_package_alias(self):
        result = CommandResult(
            command="searchsploit openssh",
            exit_code=127,
            stdout="",
            stderr="bash: line 1: searchsploit: command not found",
            duration_sec=0.1,
            target="docker",
        )
        self.assertIn("apt install exploitdb", result.render())

    def test_no_hint_for_other_failures(self):
        result = CommandResult(
            command="nmap -sV 10.0.0.5",
            exit_code=1,
            stdout="",
            stderr="QUITTING!",
            duration_sec=0.1,
            target="local",
        )
        self.assertNotIn("apt install", result.render())


class TestConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = Config.from_env()
        self.assertEqual(cfg.target, "local")
        self.assertEqual(cfg.transport, "stdio")
        self.assertFalse(cfg.disable_guardrails)

    def test_env_override(self):
        import os

        env = {
            "PARROT_MCP_TARGET": "ssh",
            "PARROT_MCP_SSH_HOST": "10.9.8.7",
            "PARROT_MCP_SSH_PORT": "2222",
            "PARROT_MCP_DISABLE_GUARDRAILS": "1",
            "PARROT_MCP_AUTH_TOKEN": "tok",
        }
        old = {k: os.environ.pop(k, None) for k in env}
        try:
            os.environ.update(env)
            cfg = Config.from_env()
            self.assertEqual(cfg.target, "ssh")
            self.assertEqual(cfg.ssh_host, "10.9.8.7")
            self.assertEqual(cfg.ssh_port, 2222)
            self.assertTrue(cfg.disable_guardrails)
            self.assertEqual(cfg.auth_token, "tok")
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_validate(self):
        cfg = Config()
        self.assertEqual(cfg.validate(), [])
        cfg.target = "ftp"
        self.assertTrue(cfg.validate())

    def test_http_non_loopback_requires_token(self):
        cfg = Config(transport="http", host="0.0.0.0")
        self.assertTrue(cfg.validate())
        cfg.auth_token = "tok"
        self.assertEqual(cfg.validate(), [])


class TestLocalExecution(unittest.IsolatedAsyncioTestCase):
    async def test_echo(self):
        result = await EXECUTOR.run("echo __unit_test_ok__", timeout=30)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("__unit_test_ok__", result.stdout)

    async def test_exit_code_and_stderr(self):
        result = await EXECUTOR.run("ls /definitely_not_here_12345", timeout=30)
        self.assertNotEqual(result.exit_code, 0)
        self.assertTrue(result.stderr)

    async def test_timeout(self):
        result = await EXECUTOR.run("sleep 5", timeout=1)
        self.assertTrue(result.timed_out)
        self.assertLess(result.duration_sec, 4)

    async def test_locate_local(self):
        found = await EXECUTOR.locate(["sh", "__definitely_missing_bin__"])
        self.assertIsNotNone(found["sh"])
        self.assertIsNone(found["__definitely_missing_bin__"])

    async def test_locate_remote_parses_paths(self):
        cfg = Config()
        cfg.target = "ssh"
        executor = Executor(cfg)

        async def fake_run(command, timeout=None):
            return CommandResult(
                command=command,
                exit_code=0,
                stdout="/usr/bin/nmap\tnmap\n\tnikto\n",
                stderr="",
                duration_sec=0.1,
                target="ssh",
            )

        with patch.object(executor, "run", fake_run):
            found = await executor.locate(["nmap", "nikto"])
        self.assertEqual(found, {"nmap": "/usr/bin/nmap", "nikto": None})

    async def test_locate_unreachable_raises(self):
        cfg = Config()
        cfg.target = "ssh"
        executor = Executor(cfg)

        async def fake_run(command, timeout=None):
            return CommandResult(
                command=command,
                exit_code=None,
                stdout="",
                stderr="",
                duration_sec=0.1,
                target="ssh",
                error="SSH connection failed",
            )

        with patch.object(executor, "run", fake_run), self.assertRaises(RuntimeError):
            await executor.locate(["nmap"])

    async def test_locate_probe_failure_raises(self):
        cfg = Config()
        cfg.target = "docker"
        executor = Executor(cfg)

        async def fake_run(command, timeout=None):
            return CommandResult(
                command=command,
                exit_code=125,
                stdout="",
                stderr="Unable to find image",
                duration_sec=0.1,
                target="docker",
            )

        with patch.object(executor, "run", fake_run), self.assertRaises(RuntimeError):
            await executor.locate(["nmap"])


class TestAuditLog(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    async def test_writes_one_json_line_per_command(self):
        path = os.path.join(self.tmp, "audit.jsonl")
        cfg = Config()
        cfg.target = "local"
        cfg.audit_log = path
        executor = Executor(cfg)
        await executor.run("echo hi", timeout=30)
        await executor.run("exit 3", timeout=30)

        entries = [
            json.loads(line)
            for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["command"], "echo hi")
        self.assertEqual(entries[0]["exit_code"], 0)
        self.assertEqual(entries[1]["exit_code"], 3)
        self.assertIn("ts", entries[0])
        self.assertNotIn("stdout", entries[0])

    async def test_off_by_default(self):
        self.assertEqual(Config().audit_log, "")


class TestDockerContainerMode(unittest.IsolatedAsyncioTestCase):
    def _executor(self):
        cfg = Config()
        cfg.target = "docker"
        cfg.docker_container = "parrot-test"
        return Executor(cfg)

    async def test_creates_missing_container(self):
        executor = self._executor()
        calls = []

        async def fake_cli(argv, timeout):
            calls.append(argv)
            if argv[1] == "inspect":
                return 1, "", "no such container"
            return 0, "", ""

        with patch.object(executor, "_docker_cli", fake_cli):
            await executor._ensure_docker_ready()
        created = [c for c in calls if c[1] == "run"]
        self.assertEqual(len(created), 1)
        self.assertIn("parrot-test", created[0])

    async def test_running_container_is_not_recreated(self):
        executor = self._executor()
        calls = []

        async def fake_cli(argv, timeout):
            calls.append(argv)
            if argv[1] == "inspect":
                return 0, "true\n", ""
            return 0, "", ""

        with patch.object(executor, "_docker_cli", fake_cli):
            await executor._ensure_docker_ready()
        self.assertFalse([c for c in calls if c[1] == "run"])


if __name__ == "__main__":
    unittest.main()
