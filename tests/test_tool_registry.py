from __future__ import annotations

from evergarden.mcp.tools import (
    APPROVED_EXECUTION_KINDS,
    TOOL_DEFINITIONS,
    WRITE_PREPARE_KINDS,
    ToolRuntime,
)


def test_every_defined_tool_is_registered_exactly_once() -> None:
    read = set(ToolRuntime._READ_HANDLERS)
    write = set(WRITE_PREPARE_KINDS)
    approved = set(APPROVED_EXECUTION_KINDS)
    assert read & write == set()
    assert read & approved == set()
    assert write & approved == set()
    assert read | write | approved == set(TOOL_DEFINITIONS)


def test_every_write_preparing_tool_is_guarded_by_table_not_prefix() -> None:
    # The write guard (receive-only + location) applies to WRITE_PREPARE_KINDS.
    # Any prepare_/preview_ tool must be in that table, so it cannot dodge the
    # guard by being added only as a read handler.
    prefixed = {name for name in TOOL_DEFINITIONS if name.startswith(("prepare_", "preview_"))}
    assert prefixed == set(WRITE_PREPARE_KINDS)
    assert set(ToolRuntime._WRITE_PAYLOADS) == set(WRITE_PREPARE_KINDS)
