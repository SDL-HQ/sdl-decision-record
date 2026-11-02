"""The verifier closure imports the standard library and cryptography, and nothing else."""

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _imports(path: Path):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node.module.split(".")[0]


def test_dr_imports_only_stdlib_and_cryptography():
    for path in sorted((ROOT / "dr").glob("*.py")):
        for name in _imports(path):
            assert name in sys.stdlib_module_names or name in ("cryptography", "dr"), f"{path.name} imports {name}"


def test_the_verifier_does_not_import_any_emitter_or_run_code_unasked():
    src = (ROOT / "dr" / "verify.py").read_text()
    assert "emitters" not in src
    # importlib is used only inside the replay branch, which the caller opts into
    assert src.count("importlib.import_module") == 1
