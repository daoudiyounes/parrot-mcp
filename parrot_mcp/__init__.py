"""Parrot MCP - Model Context Protocol server for Parrot OS security tooling."""

from . import config, executor, safety

__version__ = "1.1.0"

__all__ = ["__version__", "config", "executor", "safety"]
