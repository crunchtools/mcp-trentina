"""Tests for module shadow detection.

Validates that the shadow scanner catches Python files that shadow stdlib
modules — the core attack vector from wunderwuzzi's Claude Code bypass
(2026-08-26) where struct.py in an extracted archive shadows Python's
real struct module.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from mcp_trentina_crunchtools.sanitize.shadows import (
    STDLIB_MODULES,
    _scan_for_obfuscation,
    detect_module_shadows,
)


class TestStdlibModuleSet:
    """Verify the stdlib module set is populated and contains expected names."""

    def test_contains_struct(self) -> None:
        assert "struct" in STDLIB_MODULES

    def test_contains_common_modules(self) -> None:
        for mod in ("os", "sys", "json", "base64", "socket", "subprocess"):
            assert mod in STDLIB_MODULES

    def test_has_meaningful_size(self) -> None:
        assert len(STDLIB_MODULES) > 200


class TestObfuscationDetection:
    """Verify detection of obfuscation patterns in Python source."""

    def test_detects_exec(self) -> None:
        indicators = _scan_for_obfuscation("exec(code)")
        categories = {i.category for i in indicators}
        assert "code_execution" in categories

    def test_detects_eval(self) -> None:
        indicators = _scan_for_obfuscation("result = eval(expr)")
        categories = {i.category for i in indicators}
        assert "code_execution" in categories

    def test_detects_compile(self) -> None:
        indicators = _scan_for_obfuscation("co = compile(src, '<string>', 'exec')")
        categories = {i.category for i in indicators}
        assert "code_execution" in categories

    def test_detects_subprocess(self) -> None:
        indicators = _scan_for_obfuscation("import subprocess")
        categories = {i.category for i in indicators}
        assert "process_spawn" in categories

    def test_detects_popen(self) -> None:
        indicators = _scan_for_obfuscation("p = Popen(['ls'])")
        categories = {i.category for i in indicators}
        assert "process_spawn" in categories

    def test_detects_os_system(self) -> None:
        indicators = _scan_for_obfuscation("os.system('ls')")
        categories = {i.category for i in indicators}
        assert "process_spawn" in categories

    def test_detects_dynamic_import(self) -> None:
        indicators = _scan_for_obfuscation("m = __import__('os')")
        categories = {i.category for i in indicators}
        assert "dynamic_import" in categories

    def test_detects_chr_building(self) -> None:
        indicators = _scan_for_obfuscation(
            "x = chr(72) + chr(101) + chr(108) + chr(108)"
        )
        categories = {i.category for i in indicators}
        assert "char_building" in categories

    def test_ignores_few_chr_calls(self) -> None:
        indicators = _scan_for_obfuscation("x = chr(72) + chr(101)")
        categories = {i.category for i in indicators}
        assert "char_building" not in categories

    def test_detects_internal_import(self) -> None:
        indicators = _scan_for_obfuscation("from _struct import *")
        categories = {i.category for i in indicators}
        assert "internal_import" in categories

    def test_detects_network_access(self) -> None:
        indicators = _scan_for_obfuscation("import socket")
        categories = {i.category for i in indicators}
        assert "network_access" in categories

    def test_detects_base64_decode(self) -> None:
        indicators = _scan_for_obfuscation("data = b64decode(payload)")
        categories = {i.category for i in indicators}
        assert "obfuscation" in categories

    def test_detects_hex_escapes(self) -> None:
        indicators = _scan_for_obfuscation(r"x = '\x68\x65\x6c\x6c\x6f'")
        categories = {i.category for i in indicators}
        assert "obfuscation" in categories

    def test_detects_bytes_fromhex(self) -> None:
        indicators = _scan_for_obfuscation("cmd = bytes.fromhex('6c73')")
        categories = {i.category for i in indicators}
        assert "obfuscation" in categories

    def test_ignores_comments(self) -> None:
        indicators = _scan_for_obfuscation("# exec(dangerous_code)")
        assert len(indicators) == 0

    def test_ignores_blank_lines(self) -> None:
        indicators = _scan_for_obfuscation("\n\n\n")
        assert len(indicators) == 0

    def test_clean_code_has_no_indicators(self) -> None:
        clean = textwrap.dedent("""\
            def add(a, b):
                return a + b

            x = add(1, 2)
            print(x)
        """)
        indicators = _scan_for_obfuscation(clean)
        assert len(indicators) == 0

    def test_rehberger_struct_py_pattern(self) -> None:
        """The exact pattern from the wunderwuzzi attack: re-export real
        _struct API while exec'ing obfuscated payload."""
        malicious = textwrap.dedent("""\
            from _struct import *
            from _struct import _clearcache, error
            exec(bytes.fromhex('696d706f7274206f73').decode())
        """)
        indicators = _scan_for_obfuscation(malicious)
        categories = {i.category for i in indicators}
        assert "internal_import" in categories
        assert "code_execution" in categories
        assert "obfuscation" in categories

    def test_reports_line_numbers(self) -> None:
        code = "x = 1\nexec(payload)\ny = 2"
        indicators = _scan_for_obfuscation(code)
        assert any(i.line_number == 2 for i in indicators)


class TestDetectModuleShadows:
    """Verify directory scanning for module shadows."""

    def test_detects_struct_py_shadow(self, tmp_path: Path) -> None:
        (tmp_path / "struct.py").write_text("from _struct import *\n")
        result = detect_module_shadows(str(tmp_path))
        assert result.has_shadows
        assert result.shadows_found[0].shadows_module == "struct"
        assert result.risk_level in ("high", "critical")

    def test_detects_os_py_shadow(self, tmp_path: Path) -> None:
        (tmp_path / "os.py").write_text("import sys\n")
        result = detect_module_shadows(str(tmp_path))
        assert result.has_shadows
        assert result.shadows_found[0].shadows_module == "os"

    def test_detects_obfuscated_shadow(self, tmp_path: Path) -> None:
        (tmp_path / "struct.py").write_text(
            "from _struct import *\nexec(bytes.fromhex('6f73'))\n"
        )
        result = detect_module_shadows(str(tmp_path))
        assert result.risk_level == "critical"
        assert result.shadows_found[0].is_obfuscated

    def test_no_shadows_in_clean_directory(self, tmp_path: Path) -> None:
        (tmp_path / "mymodule.py").write_text("x = 1\n")
        (tmp_path / "utils.py").write_text("def helper(): pass\n")
        result = detect_module_shadows(str(tmp_path))
        assert not result.has_shadows
        assert result.risk_level == "low"

    def test_counts_scanned_files(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")
        (tmp_path / "c.txt").write_text("not python\n")
        result = detect_module_shadows(str(tmp_path))
        assert result.files_scanned == 2

    def test_ignores_non_python_files(self, tmp_path: Path) -> None:
        (tmp_path / "struct.txt").write_text("not python\n")
        (tmp_path / "struct.c").write_text("not python\n")
        result = detect_module_shadows(str(tmp_path))
        assert not result.has_shadows

    def test_detects_package_shadow(self, tmp_path: Path) -> None:
        pkg = tmp_path / "json"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("from _json import *\n")
        result = detect_module_shadows(str(tmp_path))
        assert result.has_shadows
        assert result.shadows_found[0].shadows_module == "json"

    def test_nonexistent_directory_returns_empty(self) -> None:
        result = detect_module_shadows("/nonexistent/path")
        assert not result.has_shadows
        assert result.files_scanned == 0

    def test_multiple_shadows(self, tmp_path: Path) -> None:
        (tmp_path / "struct.py").write_text("from _struct import *\n")
        (tmp_path / "os.py").write_text("pass\n")
        (tmp_path / "json.py").write_text("pass\n")
        result = detect_module_shadows(str(tmp_path))
        assert len(result.shadows_found) == 3

    def test_to_dict_serialization(self, tmp_path: Path) -> None:
        (tmp_path / "struct.py").write_text("exec('bad')\n")
        result = detect_module_shadows(str(tmp_path))
        d = result.to_dict()
        assert "shadows" in d
        assert d["has_shadows"] is True
        assert d["shadows"][0]["shadows_module"] == "struct"
        assert d["shadows"][0]["is_obfuscated"] is True

    def test_empty_directory(self, tmp_path: Path) -> None:
        result = detect_module_shadows(str(tmp_path))
        assert not result.has_shadows
        assert result.files_scanned == 0
        assert result.risk_level == "low"

    def test_wunderwuzzi_full_scenario(self, tmp_path: Path) -> None:
        """Simulate the full wunderwuzzi attack archive layout."""
        (tmp_path / "README.txt").write_text("Notebook catalogue\n")
        (tmp_path / "accession-map.csv").write_text("id,title\n")
        (tmp_path / "MANIFEST.sha256").write_text("abc123  file1\n")
        for i in range(7):
            (tmp_path / f"record-{i}.json.b85z").write_text("encoded\n")
        (tmp_path / "decoder-darwin").write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

        malicious_struct = textwrap.dedent("""\
            from _struct import *
            from _struct import _clearcache, error
            _r = __import__
            _o = _r('os')
            _s = _r('subprocess')
            _b = bytes.fromhex
            exec(compile(_b('70617373').decode(), '<s>', 'exec'))
        """)
        (tmp_path / "struct.py").write_text(malicious_struct)

        result = detect_module_shadows(str(tmp_path))
        assert result.has_shadows
        assert result.risk_level == "critical"
        shadow = result.shadows_found[0]
        assert shadow.shadows_module == "struct"
        assert shadow.is_obfuscated
        categories = {i.category for i in shadow.obfuscation_indicators}
        assert "internal_import" in categories
        assert "code_execution" in categories
        assert "obfuscation" in categories
        # _r = __import__ aliases the builtin to evade __import__() call detection
        # — a known regex limitation; the other indicators still catch it
        assert "process_spawn" in categories
