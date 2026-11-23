"""Integration tests: in-process MCP client against the registered server."""

import unittest
from unittest.mock import patch

from fastmcp import Client

from parrot_mcp.executor import CommandResult
from parrot_mcp.server import build_parser, mcp
from parrot_mcp.state import EXECUTOR


def _text(result) -> str:
    return result.content[0].text


class TestToolRegistration(unittest.IsolatedAsyncioTestCase):
    async def test_all_tools_registered(self):
        async with Client(mcp) as client:
            tools = await client.list_tools()
        names = {t.name for t in tools}
        expected = {
            "run_command",
            "set_execution_target",
            "get_execution_status",
            "system_info",
            "check_tools",
            "docker_manage",
            "list_files",
            "get_file_info",
            "get_tool_help",
            "nmap_scan",
            "masscan_scan",
            "amass_enum",
            "sublist3r_scan",
            "whois_lookup",
            "dns_recon",
            "nikto_scan",
            "whatweb_scan",
            "gobuster_scan",
            "wpscan_scan",
            "dirsearch_scan",
            "ssl_analysis",
            "searchsploit_search",
            "sqlmap_scan",
            "msf_run",
            "hydra_attack",
            "hashcat_crack",
            "john_crack",
            "anonsurf_control",
            "macchanger_spoof",
            "proxychains_exec",
            "tor_status",
            "theharvester_search",
        }
        missing = expected - names
        self.assertEqual(missing, set(), f"missing tools: {missing}")
        self.assertGreaterEqual(len(tools), 30)

    async def test_prompts_and_resources_registered(self):
        async with Client(mcp) as client:
            prompts = await client.list_prompts()
            resources = await client.list_resources()
        self.assertEqual(len(prompts), 6)
        uris = {str(r.uri) for r in resources}
        self.assertIn("parrot://status", uris)
        self.assertIn("parrot://tools", uris)


class TestRunCommand(unittest.IsolatedAsyncioTestCase):
    async def test_echo_through_mcp(self):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "run_command", {"command": "echo __mcp_integration_ok__"}
            )
        self.assertIn("__mcp_integration_ok__", _text(result))

    async def test_refuses_destructive_without_confirmation(self):
        async with Client(mcp) as client:
            result = await client.call_tool("run_command", {"command": "rm -rf /"})
        self.assertIn("REFUSED", _text(result))
        self.assertIn("confirm_destructive", _text(result))

    async def test_confirmed_destructive_reaches_executor_with_warning(self):
        captured = {}

        async def fake_run(command, timeout=None):
            captured["command"] = command
            return CommandResult(
                command=command,
                exit_code=0,
                stdout="stub",
                stderr="",
                duration_sec=0.1,
                target=EXECUTOR.target,
            )

        with patch.object(EXECUTOR, "run", fake_run):
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "run_command",
                    {"command": "rm -rf /", "confirm_destructive": True},
                )
        self.assertEqual(captured["command"], "rm -rf /")
        self.assertIn("WARNING", _text(result))

    async def test_structured_tool_guardrail_catches_interpolated_values(self):
        async with Client(mcp) as client:
            result = await client.call_tool(
                "nmap_scan", {"target": "127.0.0.1", "extra_args": "; rm -rf /"}
            )
        self.assertIn("REFUSED", _text(result))

    async def test_unknown_scan_type_is_an_error(self):
        from fastmcp.exceptions import ToolError

        async with Client(mcp) as client:
            with self.assertRaises(ToolError) as ctx:
                await client.call_tool(
                    "nmap_scan", {"target": "127.0.0.1", "scan_type": "nonsense"}
                )
        self.assertIn("scan_type", str(ctx.exception).lower())


class TestStatusTools(unittest.IsolatedAsyncioTestCase):
    async def test_get_execution_status(self):
        async with Client(mcp) as client:
            result = await client.call_tool("get_execution_status", {})
        self.assertIn("execution target", _text(result))

    async def test_check_tools(self):
        async with Client(mcp) as client:
            result = await client.call_tool("check_tools", {"tools": ["sh", "__missing_bin__"]})
        self.assertIn("OK   sh", _text(result))
        self.assertIn("MISS __missing_bin__", _text(result))

    async def test_get_tool_help_rejects_shell_metacharacters(self):
        from fastmcp.exceptions import ToolError

        for bad in ["nmap; id", "nmap && id", "$(id)", "nmap|id", ""]:
            with self.subTest(tool=bad):
                async with Client(mcp) as client:
                    with self.assertRaises(ToolError):
                        await client.call_tool("get_tool_help", {"tool": bad})

    async def test_get_tool_help_builds_a_safe_command(self):
        captured = {}

        async def fake_run(command, timeout=None):
            captured["command"] = command
            return CommandResult(
                command=command,
                exit_code=0,
                stdout="usage: nmap ...",
                stderr="",
                duration_sec=0.1,
                target=EXECUTOR.target,
            )

        with patch.object(EXECUTOR, "run", fake_run):
            async with Client(mcp) as client:
                result = await client.call_tool("get_tool_help", {"tool": "nmap"})
        self.assertIn("usage: nmap", _text(result))
        command = captured["command"]
        self.assertIn("command -v nmap", command)
        self.assertIn("--help", command)
        self.assertIn("-h", command)


class TestCliFlags(unittest.IsolatedAsyncioTestCase):
    def test_docker_one_liner(self):
        args = build_parser().parse_args(["--mode", "docker", "--container", "parrot"])
        self.assertEqual(args.mode, "docker")
        self.assertEqual(args.container, "parrot")

    def test_ssh_one_liner(self):
        args = build_parser().parse_args(
            [
                "--mode",
                "ssh",
                "--host",
                "10.0.0.5",
                "--user",
                "root",
                "--password",
                "pw",
            ]
        )
        self.assertEqual(
            (args.mode, args.host, args.user, args.password),
            ("ssh", "10.0.0.5", "root", "pw"),
        )

    def test_legacy_target_alias_still_works(self):
        self.assertEqual(build_parser().parse_args(["--target", "docker"]).mode, "docker")

    def test_http_flags_do_not_clash_with_ssh_host(self):
        args = build_parser().parse_args(
            ["--http-host", "0.0.0.0", "--http-port", "9000", "--host", "10.1.1.1"]
        )
        self.assertEqual((args.http_host, args.http_port, args.host), ("0.0.0.0", 9000, "10.1.1.1"))


if __name__ == "__main__":
    unittest.main()
