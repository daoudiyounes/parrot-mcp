"""Process-wide singletons shared by all tool modules."""

from __future__ import annotations

from .config import Config
from .executor import Executor

config = Config.from_env()
EXECUTOR = Executor(config)
